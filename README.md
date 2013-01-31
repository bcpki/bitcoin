Goal
====

The goal of the BCPKI-project (blockchain-PKI) is to establish a root CA inside the blockchain.
What has been done here

What has been done
==================

First, we have drafted a quite general specification for bitcoin certificates (protobuf messages) that allow for a variety of payment protocols (e.g. static as well as customer-side-generated payment addresses). This part has surely been done elsewhere as well and is orthogonal to the goal of this project. What is new here is the signatures under the certificates.

We have patched the bitcoind to handle certificates, submit signatures to the blockchain, verify certificates against the blockchain, and pay to addresses contained in the blockchain.

Details can be found in the wiki.
