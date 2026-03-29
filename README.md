# Decentralized PKI with Threshold Signatures

A Decentralized Blockchain-based Public Key Infrastructure built on top of Hyperledger Fabric.

## Project Structure

This repository is organized into these main components:

*   **[`/chaincode`](./chaincode)**
    Contains the Go-based Fabric smart contracts. It handles decentralized CA logic, member join requests, voting mechanics (approval limits), and key management on the ledger.
*   **[`/peer-app`](./peer-app)**
    The off-chain Go application running the TSS nodes. This application interfaces with the Fabric and coordinates distributed key generation (DKG) and signing with other peer nodes. It also holds the `benchmarks/` directory containing scripts for measurement and the captured runs contained in the thesis.
*   **[`/deployment`](./deployment)**
    Contains generator scripts, `docker-compose` and artifacts to automatically provide crypto-materials, deploy the Fabric network, install the chaincode, and bootstrap the TSS peers. **(See the README here for detailed setup and execution steps).**
*   **[`/explorer`](../explorer)**
    Configuration and deployment files for Hyperledger Explorer to provide a dashboard for monitoring blocks, transactions, and chaincode executions on the deployed blockchain.
*   **[`/documentation`](../documentation)**
    Documentation related to the masters thesis including an excel file for proposal comparison, bibtex files that were generated during the research process and the final presentation.

## Getting Started

To spin up the network, install the components, and run the system, refer to the guide in the deployment folder:
 **[Deployment Instructions & Network Setup](./deployment/README.md)**