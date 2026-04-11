#!/usr/bin/env bash
# =======================================================================
# DocuVault Final — Test runner
#
# Called by the autograding workflow for each test group.
# Manages the docker-compose cluster lifecycle.
#
# Usage:  ./run_test_final.sh <test_group>
# Exit:   0 = PASS, 1 = FAIL
#
# DO NOT MODIFY.
# =======================================================================

set -euo pipefail

TEST_NAME="${1:?Usage: run_test_final.sh <test_group>}"
COMPOSE_PROJECT="docuvault-test"
HOST="localhost"
COORD_PORT=8080
STORAGE_A_PORT=9001
STORAGE_B_PORT=9002
MAX_WAIT=45
TEST_CLIENT="/tmp/docuvault_test_client_final"

# The shared secret used in the test compose override.
TEST_SECRET="test_secret_key_for_grading"

# -------------------------------------------------------------------
# Create a compose override that:
#   1. Exposes storage ports for direct testing (HMAC rejection).
#   2. Sets a short lock timeout for the deadlock test.
#   3. Sets a known shared secret.
# -------------------------------------------------------------------
OVERRIDE_FILE="/tmp/docuvault-test-override.yml"
cat > "$OVERRIDE_FILE" <<EOF
version: "3.8"
services:
  coordinator:
    environment:
      - DOCUVAULT_SECRET=${TEST_SECRET}
      - LOCK_TIMEOUT_SECONDS=3
  storage-a:
    ports:
      - "${STORAGE_A_PORT}:9001"
    environment:
      - DOCUVAULT_SECRET=${TEST_SECRET}
  storage-b:
    ports:
      - "${STORAGE_B_PORT}:9002"
    environment:
      - DOCUVAULT_SECRET=${TEST_SECRET}
EOF

COMPOSE_CMD="docker compose -p ${COMPOSE_PROJECT} -f docker-compose.yml -f ${OVERRIDE_FILE}"

# -------------------------------------------------------------------
# Cleanup function
# -------------------------------------------------------------------
cleanup() {
    echo "Cleaning up..."
    # Unpause any paused containers.
    docker unpause "${COMPOSE_PROJECT}-storage-b-1" 2>/dev/null || true
    docker unpause "${COMPOSE_PROJECT}_storage-b_1" 2>/dev/null || true
    # Tear down the cluster.
    $COMPOSE_CMD down --volumes --remove-orphans 2>/dev/null || true
    rm -f "$OVERRIDE_FILE"
}
trap cleanup EXIT

# -------------------------------------------------------------------
# Start the cluster
# -------------------------------------------------------------------
start_cluster() {
    echo "Starting cluster..."
    $COMPOSE_CMD down --volumes --remove-orphans 2>/dev/null || true
    $COMPOSE_CMD up -d --build 2>&1

    if [ $? -ne 0 ]; then
        echo "[FAIL] docker-compose up failed"
        exit 1
    fi

    # Wait for coordinator to accept TCP connections.
    echo "Waiting for coordinator on port $COORD_PORT..."
    for i in $(seq 1 "$MAX_WAIT"); do
        if nc -z "$HOST" "$COORD_PORT" 2>/dev/null; then
            echo "Coordinator ready after ${i}s"
            return 0
        fi
        if [ "$i" -eq "$MAX_WAIT" ]; then
            echo "[FAIL] Coordinator not ready within ${MAX_WAIT}s"
            $COMPOSE_CMD logs 2>&1 || true
            exit 1
        fi
        sleep 1
    done
}

# -------------------------------------------------------------------
# Get container name (handles both naming conventions)
# -------------------------------------------------------------------
get_container_name() {
    local service="$1"
    # Try new naming (docker-compose v2: project-service-1)
    local name="${COMPOSE_PROJECT}-${service}-1"
    if docker inspect "$name" >/dev/null 2>&1; then
        echo "$name"
        return
    fi
    # Try old naming (docker-compose v1: project_service_1)
    name="${COMPOSE_PROJECT}_${service}_1"
    if docker inspect "$name" >/dev/null 2>&1; then
        echo "$name"
        return
    fi
    echo ""
}

# -------------------------------------------------------------------
# Run individual tests
# -------------------------------------------------------------------

run_test() {
    echo "Running test group: $TEST_NAME"
    echo "---"

    case "$TEST_NAME" in

    cluster_start|login_routing|read_replica|write_lock)
        # Pure TCP tests — test client handles everything.
        start_cluster
        "$TEST_CLIENT" "$HOST" "$COORD_PORT" "$TEST_NAME"
        return $?
        ;;

    write_replication)
        start_cluster

        # Run the TCP portion (writes and reads).
        "$TEST_CLIENT" "$HOST" "$COORD_PORT" "$TEST_NAME"
        TCP_EXIT=$?

        if [ "$TCP_EXIT" -ne 0 ]; then
            return "$TCP_EXIT"
        fi

        # Volume inspection: check both storage nodes have data.
        echo "--- Volume inspection ---"
        SA_CONTAINER=$(get_container_name "storage-a")
        SB_CONTAINER=$(get_container_name "storage-b")

        if [ -z "$SA_CONTAINER" ] || [ -z "$SB_CONTAINER" ]; then
            echo "[FAIL] Could not find storage container names"
            return 1
        fi

        SA_BLOCKS=$(docker exec "$SA_CONTAINER" \
            sh -c 'ls /data/store/blocks/ 2>/dev/null | wc -l' 2>/dev/null || echo "0")
        SB_BLOCKS=$(docker exec "$SB_CONTAINER" \
            sh -c 'ls /data/store/blocks/ 2>/dev/null | wc -l' 2>/dev/null || echo "0")

        echo "Storage-A block count: $SA_BLOCKS"
        echo "Storage-B block count: $SB_BLOCKS"

        if [ "$SA_BLOCKS" -gt 0 ] && [ "$SB_BLOCKS" -gt 0 ]; then
            echo "  [OK]   Both storage nodes have block data"
        else
            echo "  [FAIL] At least one storage node has no block data"
            return 1
        fi

        return 0
        ;;

    delete_replication)
        start_cluster

        # Write a file first, then run the delete test.
        "$TEST_CLIENT" "$HOST" "$COORD_PORT" "$TEST_NAME"
        TCP_EXIT=$?

        if [ "$TCP_EXIT" -ne 0 ]; then
            return "$TCP_EXIT"
        fi

        # Verify deleted file's blocks are cleaned up.
        # We check that the index doesn't reference the deleted path.
        echo "--- Volume inspection (delete) ---"
        SA_CONTAINER=$(get_container_name "storage-a")
        SB_CONTAINER=$(get_container_name "storage-b")

        if [ -z "$SA_CONTAINER" ] || [ -z "$SB_CONTAINER" ]; then
            echo "[FAIL] Could not find storage container names"
            return 1
        fi

        # Check that the deleted file is not in either index.
        SA_HAS_DEL=$(docker exec "$SA_CONTAINER" \
            sh -c 'grep -l "delrepl.txt" /data/store/index* 2>/dev/null | wc -l' \
            2>/dev/null || echo "0")
        SB_HAS_DEL=$(docker exec "$SB_CONTAINER" \
            sh -c 'grep -l "delrepl.txt" /data/store/index* 2>/dev/null | wc -l' \
            2>/dev/null || echo "0")

        if [ "$SA_HAS_DEL" -eq 0 ] && [ "$SB_HAS_DEL" -eq 0 ]; then
            echo "  [OK]   Deleted file absent from both storage indexes"
        else
            echo "  [FAIL] Deleted file still present in at least one index"
            return 1
        fi

        return 0
        ;;

    hmac_rejection)
        start_cluster

        # Wait for storage-a to be ready.
        echo "Waiting for storage-a on port $STORAGE_A_PORT..."
        for i in $(seq 1 "$MAX_WAIT"); do
            if nc -z "$HOST" "$STORAGE_A_PORT" 2>/dev/null; then
                echo "Storage-A ready after ${i}s"
                break
            fi
            if [ "$i" -eq "$MAX_WAIT" ]; then
                echo "[FAIL] Storage-A not ready"
                exit 1
            fi
            sleep 1
        done

        # Run the HMAC rejection test (connects directly to storage-a).
        "$TEST_CLIENT" "$HOST" "$COORD_PORT" "$TEST_NAME" \
            "$HOST" "$STORAGE_A_PORT"
        TCP_EXIT=$?

        # Check storage-a logs for the rejection warning.
        echo "--- Log inspection ---"
        SA_CONTAINER=$(get_container_name "storage-a")
        if [ -n "$SA_CONTAINER" ]; then
            WARN_COUNT=$(docker logs "$SA_CONTAINER" 2>&1 | \
                grep -c "WARN.*rejected.*unauthenticated" || echo "0")
            if [ "$WARN_COUNT" -gt 0 ]; then
                echo "  [OK]   Storage-A logged HMAC rejection warning"
            else
                echo "  [FAIL] No HMAC rejection warning in storage-a logs"
                TCP_EXIT=1
            fi
        fi

        return "$TCP_EXIT"
        ;;

    deadlock_timeout)
        start_cluster

        # Pause storage-b so the coordinator's forwarding hangs.
        echo "Pausing storage-b..."
        SB_CONTAINER=$(get_container_name "storage-b")
        if [ -z "$SB_CONTAINER" ]; then
            echo "[FAIL] Could not find storage-b container"
            exit 1
        fi
        docker pause "$SB_CONTAINER"

        # Run the deadlock timeout test.
        # The test client sends writes that will hang, expecting errors.
        "$TEST_CLIENT" "$HOST" "$COORD_PORT" "$TEST_NAME" || true

        # Unpause storage-b before checking logs.
        docker unpause "$SB_CONTAINER" 2>/dev/null || true

        # Check coordinator logs for the forced lock release warning.
        echo "--- Log inspection ---"
        COORD_CONTAINER=$(get_container_name "coordinator")
        if [ -z "$COORD_CONTAINER" ]; then
            echo "[FAIL] Could not find coordinator container"
            exit 1
        fi

        WARN_COUNT=$(docker logs "$COORD_CONTAINER" 2>&1 | \
            grep -c "WARN.*forced lock release" || echo "0")

        if [ "$WARN_COUNT" -gt 0 ]; then
            echo "  [OK]   Coordinator logged forced lock release warning"
            echo "[PASS] deadlock_timeout"
            return 0
        else
            echo "  [FAIL] No forced lock release warning in coordinator logs"
            echo "Coordinator logs (last 20 lines):"
            docker logs "$COORD_CONTAINER" 2>&1 | tail -20
            echo "[FAIL] deadlock_timeout"
            return 1
        fi
        ;;

    rpc_structure)
        # Source code inspection — no cluster needed.
        echo "--- Source inspection ---"

        PASS=true

        # Check for StorageClient class declaration.
        if grep -rq "class StorageClient" src/; then
            echo "  [OK]   StorageClient class found"
        else
            echo "  [FAIL] StorageClient class not found in src/"
            PASS=false
        fi

        # Check for required method signatures.
        if grep -rq "AckResult.*write\|AckResult.*read\|AckResult.*remove" src/; then
            echo "  [OK]   Required RPC method signatures found"
        else
            echo "  [FAIL] Required RPC methods (write/read/remove) not found"
            PASS=false
        fi

        if $PASS; then
            echo "[PASS] rpc_structure"
            return 0
        else
            echo "[FAIL] rpc_structure"
            return 1
        fi
        ;;

    *)
        echo "Unknown test group: $TEST_NAME"
        exit 1
        ;;
    esac
}

# -------------------------------------------------------------------
# Entry point
# -------------------------------------------------------------------
run_test
EXIT_CODE=$?
echo "---"
exit "$EXIT_CODE"
