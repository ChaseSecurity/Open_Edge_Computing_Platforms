# Dissecting Open Edge Computing Platforms: Ecosystem, Usage, and Security Risks

The source code for the paper *Dissecting Open Edge Computing Platforms: Ecosystem, Usage, and Security Risks*, **ACSAC 2024**.

More introdution in [Project website](https://chasesecurity.github.io/Open_Edge_Computing_Platforms/).

## Overview

Emerging in recent years, open edge computing platforms (OECPs) claim large-scale edge nodes, the extensive usage and adoption, as well as the openness to any third parties to join as edge nodes. For instance, OneThingCloud, a major OECP operated in China, advertises 5 million edge nodes, 70TB bandwidth, and 1,500PB storage. However, little information is publicly available for such OECPs with regards to their technical mechanisms and involvement in edge computing activities. Furthermore, different from known edge computing paradigms, OECPs feature an open ecosystem wherein any third party can participate as edge nodes and earn revenue for the contribution of computing and bandwidth resources, which, however, can introduce byzantine or even malicious edge nodes and thus break the traditional threat model for edge computing. In this study, we conduct the first empirical study on two representative OECPs, which is made possible through the deployment of edge nodes across locations, the efficient and semi-automatic analysis of edge traffic as well as the carefully designed security experiments. As the results, a set of novel findings and insights have been distilled with regards to their technical mechanisms, the landscape of edge nodes, the usage and adoption, and the practical security/privacy risks. Particularly, millions of daily active edge nodes have been observed, which feature a wide distribution in the network space and the extensive adoption in content delivery towards end users of 16 popular Internet services. Also, multiple practical and concerning security risks have been identified along with acknowledgements received from relevant parties, e.g., the exposure of long-term and cross-edge-node credentials, the co-location with malicious activities of diverse categories, the failures of TLS certificate verification, the extensive information leakage against end users, etc. 

## Code

We released the source code for all the tools we developed during our works.

- [Capturing Edge Traffic](./deployment)
- [The Edge Traffic Analyzer](./traffic_analyzer)

More details can be found in READMEs of subfolders.

## Bibtex
```
@article{bi2024dissectingopenedgecomputing,
      title={Dissecting Open Edge Computing Platforms: Ecosystem, Usage, and Security Risks}, 
      author={Yu Bi and Mingshuo Yang and Yong Fang and Xianghang Mi and Shanqing Guo and Shujun Tang and Haixin Duan},
      year={2024},
      eprint={2404.09681},
      archivePrefix={arXiv},
      url={https://arxiv.org/abs/2404.09681}
}
```
