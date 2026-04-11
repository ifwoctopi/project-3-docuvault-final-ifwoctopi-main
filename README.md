[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/zVpLa951)
# DocuVault — Final

---

> Understanding the below will help you answer some of the questions during the tech interview.

## Architecture Overview

*Describe your 3-node architecture at a high level. How do the Coordinator and Storage nodes interact? What role does each container play?*

## Binary Message Protocol

*Document your protocol format:*

- *What is your magic number?*
- *What message types did you define and what are their codes?*
- *How is the payload structured for each message type (e.g., how do you encode path, owner, perms, and file data into a single payload)?*
- *Where does the HMAC tag sit in the frame, and what bytes does it cover?*

## RPC Design

*Describe your StorageClient class. How does it abstract the binary protocol so the Coordinator's logic reads like regular function calls? What does error handling look like from the Coordinator's perspective?*

## Write Locking and Deadlock Recovery

*Explain how your per-file write locking works. What happens when two concurrent writes target the same file? How does the timeout-based deadlock recovery mechanism work? What trade-offs did you make?*

## Replication Strategy

*Describe how writes are replicated to both storage nodes. What happens if one node fails mid-write? How do you handle the inconsistency?*

## Inter-Node Authentication

*How do you compute and verify the HMAC tag? What happens when a storage node receives a message with an invalid HMAC?*

## How to Build and Run

```bash
docker-compose up
```
