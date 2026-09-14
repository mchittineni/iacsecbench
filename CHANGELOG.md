# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Correction to earlier entries.** Release notes below are generated from commit
> messages and are left unedited, because a changelog that is rewritten stops being
> a record. Two claims in them do not hold, and are corrected here rather than
> silently removed:
>
> - Entries describing a **345-case** benchmark refer to catalogue *declarations*,
>   not configurations on disk. 44 internal cases exist, plus 4 external, for 48
>   admissible cases. The **175** external cases are likewise declared by manifest;
>   two of the three external collections contain no Terraform files at all.
> - Any perfect or near-perfect score attributed to the reference implementation
>   came from `evaluation/score.py`, which multiplies corpus counts by hardcoded
>   rates and pins the reference to 100%. It measures nothing. On measured results
>   the reference implementation ranks **last** on this corpus.
>
> Measured results: [`leaderboard/results.csv`](leaderboard/results.csv) and
> `results/evaluation.json`. See [`results/README.md`](results/README.md) for which
> artefacts are measurements and which are not.

Releases are published automatically by [`release-please.yml`](.github/workflows/release-please.yml) adhering to Semantic Versioning:

- **`PATCH` (x.y.Z)** — Re-measurement on an unchanged corpus, tooling and documentation (`results/**`, `leaderboard/**`, `docs/**`, `paper/**`).
- **`MINOR` (x.Y.0)** — New corpus cases, new canonical controls, or new rule mappings (`benchmark/**`, `evaluation/control_map.json`).
- **`MAJOR` (X.0.0)** — Changes to what a reported number means: the control taxonomy, the matching criteria, or the admissibility gate.

## [2.1.0](https://github.com/mchittineni/iacsecbench/compare/v2.0.0...v2.1.0) (2026-09-14)


### Features

* add optional paired transition verification ([#88](https://github.com/mchittineni/iacsecbench/issues/88)) ([4cc8de2](https://github.com/mchittineni/iacsecbench/commit/4cc8de29fde4e0d47c082a66d1cb05a62c9f6ad5))

## [2.0.0](https://github.com/mchittineni/iacsecbench/compare/v1.3.1...v2.0.0) (2026-08-20)


### ⚠ BREAKING CHANGES

* **license:** Update license to MIT

### Features

* **benchmark:** cover all 26 controls and add an unlabelled external subset ([5dc59cd](https://github.com/mchittineni/iacsecbench/commit/5dc59cd7d516bfca8f0080a77d05d5c90488d3c2))
* **evaluation:** measure the external subset and cut unverified mappings to two ([1117ec6](https://github.com/mchittineni/iacsecbench/commit/1117ec6898fe2b6ff63f18f037e83cb14d356021))


### Bug Fixes

* **evaluation:** clear the bandit and pylint findings in the external subset ([f2aea3e](https://github.com/mchittineni/iacsecbench/commit/f2aea3ebd5dbe003c6181167b1b43edab991a2ea))
* **experiments:** resolve git absolutely and split the fetch out of fetch_one ([eeaa790](https://github.com/mchittineni/iacsecbench/commit/eeaa790d1a2bf4b14e7e2b86f9f113eed4856521))
* **experiments:** stop the figure gate failing on host-dependent latency ([a95e28b](https://github.com/mchittineni/iacsecbench/commit/a95e28b95a256764ee431e09a24af64bc6f01c5c))
* **license:** Update license to MIT ([7fb9574](https://github.com/mchittineni/iacsecbench/commit/7fb95742267c3f0e35636f86a6be2c3ef7df36a0))

## [1.3.1](https://github.com/mchittineni/iacsecbench/compare/v1.3.0...v1.3.1) (2026-08-07)


### Bug Fixes

* **Readme:** Update README ([7bd9246](https://github.com/mchittineni/iacsecbench/commit/7bd92461283d4e3a09ed3923c13129fa74f69e06))
* **workflows:** restore Trivy cache warming and the Pages artifact action ([6c17c56](https://github.com/mchittineni/iacsecbench/commit/6c17c56b64e7803aca58541c252e78c8f04cb869))

## [1.3.0](https://github.com/mchittineni/iacsecbench/compare/v1.2.0...v1.3.0) (2026-08-03)


### Features

* **benchmark:** update corpus generator and dataset documentation ([852b665](https://github.com/mchittineni/iacsecbench/commit/852b6656a108d786393bbdcc8afad4a4c03f4042))
* **benchmark:** update corpus generator module ([965f135](https://github.com/mchittineni/iacsecbench/commit/965f13523ef3753141f34eead40c8887638bf1ae))
* **evaluation:** add baseline evaluation framework and documentation ([edfc2e4](https://github.com/mchittineni/iacsecbench/commit/edfc2e4e7172123ea62549170a14841853290c04))
* **evaluation:** add synthetic guard module and test suite updates ([83a4fd8](https://github.com/mchittineni/iacsecbench/commit/83a4fd8114195867f9f4eb46df3139837475a929))
* **evaluation:** update evaluation protocol, baseline runners, and test suite ([a05020e](https://github.com/mchittineni/iacsecbench/commit/a05020e2c3421eca14e3969f007ad4831f09a3be))
* **evaluation:** update statistical analysis, normalization, and baseline runner modules ([68d7323](https://github.com/mchittineni/iacsecbench/commit/68d73230603b92878fb835ebe624c5c02239b747))
* **evaluation:** update stats analysis, normalization, and test suites ([cd9bbf4](https://github.com/mchittineni/iacsecbench/commit/cd9bbf46e1b5933171e8215643bfee6cb0d24b73))
* **experiments:** update reproducibility scripts and experiment documentation ([5e81b08](https://github.com/mchittineni/iacsecbench/commit/5e81b089a6dd57a145a6d6a07ba837d1d2683c98))
* **experiments:** update reproduction harness and chart generators ([a70aced](https://github.com/mchittineni/iacsecbench/commit/a70aced3676984dd669bcf8639055e564340f0df))
* **experiments:** update run_all.sh reproduction script ([698f21e](https://github.com/mchittineni/iacsecbench/commit/698f21edccb5822a92d9ad5955172a711299effe))
* **infrastructure:** update infrastructure CIS benchmark policies ([80009bc](https://github.com/mchittineni/iacsecbench/commit/80009bc10e0db1197a25be119188b8fe1d40a0cb))
* **pipeline:** add obsidian sync tool and pipeline documentation ([9fab10f](https://github.com/mchittineni/iacsecbench/commit/9fab10f0889947fedb509c09fc8fc2cd9c73b9b2))
* **pipeline:** update obsidian sync engine and evaluation test harness ([ee4e53c](https://github.com/mchittineni/iacsecbench/commit/ee4e53cabf985f429e9d2cf826aae46b84d65de0))
* **pipeline:** update obsidian sync script ([8b53a12](https://github.com/mchittineni/iacsecbench/commit/8b53a12661829775e9b98e9a29e7228da0b7c7f7))
* **pipeline:** update obsidian vault sync engine ([9d9a74e](https://github.com/mchittineni/iacsecbench/commit/9d9a74eb8b59e718aaa5e8b9510c482b78401c6c))
* **pipeline:** update obsidian vault sync engine and documentation ([50a5ef7](https://github.com/mchittineni/iacsecbench/commit/50a5ef79bee67a84c4c530a7a3fc4493f3923d9a))
* **security_framework:** update OPA benchmark policies ([cba5c67](https://github.com/mchittineni/iacsecbench/commit/cba5c671b7fb7b6253708809f9d72415258953dd))
* **security_framework:** update policy engine and framework documentation ([480595c](https://github.com/mchittineni/iacsecbench/commit/480595c9a6ce40996f7c3d8966a8b65080292764))


### Bug Fixes

* **pre-commit:** update trivy test cases to match new output format ([d76be62](https://github.com/mchittineni/iacsecbench/commit/d76be628d0e7decae6c738eeaf83bfc2ffef75bb))

## [Unreleased]

### Features

* **evaluation:** add baseline evaluation suite (`evaluation/run_baselines.py`, `stats.py`, `corpus.py`, `normalize.py`), execution script (`experiments/run_baselines.sh`), and synthetic scoring guard (`IACSECBENCH_ALLOW_SYNTHETIC=1`)
* **docs:** complete comprehensive markdown (`.md`) documentation across all repository component directories (`data/`, `paper/`, `results/`, `terraform/`, `evaluation/`, `experiments/`, `security_framework/`)
* **obsidian-sync:** add automated Obsidian Vault synchronization pipeline with daily notes, knowledge graphs, and IEEE paper research workspace ([`pipeline/sync_to_obsidian.py`](file:///Users/manideepchittineni/Desktop/GitHub/Personal/iacsecbench/pipeline/sync_to_obsidian.py))
* **experiments:** enhance `experiments/run_all.sh` to trigger Obsidian daily knowledge graph sync automatically upon experiment execution

## [1.2.0](https://github.com/mchittineni/iacsecbench/compare/v1.1.0...v1.2.0) (2026-07-30)


### Features

* **benchmark:** add external validation framework ([3d67d97](https://github.com/mchittineni/iacsecbench/commit/3d67d97d4c67ee6373f75c4d22dfab06648b469f))

## [1.1.0](https://github.com/mchittineni/iacsecbench/compare/v1.0.1...v1.1.0) (2026-07-30)


### Features

* **threat-model:** added new threat model for project upgrade ([c83fbc5](https://github.com/mchittineni/iacsecbench/commit/c83fbc5c03320ef3277ce2bec7e276bcafd0a820))


### Bug Fixes

* **benchmark:** update benchmark results for project upgrade ([36c0c10](https://github.com/mchittineni/iacsecbench/commit/36c0c1041c9c59c320f05b195a2a2d9319ea947d))
* **docs:** update documentation for project upgrade ([4780961](https://github.com/mchittineni/iacsecbench/commit/4780961dc36ac45a73a7a5d90da61846bebe2dbf))
* **scripts:** update code quality and compliance checkers ([fbba130](https://github.com/mchittineni/iacsecbench/commit/fbba1305e27a5eb5f3762815873edeb670339aed))
* **scripts:** update code quality and compliance checkers ([d56f4c0](https://github.com/mchittineni/iacsecbench/commit/d56f4c09a2f0b3d5383b8a5ed425032d4817bfaf))

## [1.0.1](https://github.com/mchittineni/iacsecbench/compare/v1.0.0...v1.0.1) (2026-07-28)

### Bug Fixes

- **changelog:** update changelog for release-please workflow changes ([da2ef97](https://github.com/mchittineni/iacsecbench/commit/da2ef971a1675a7b00293153ee6cf10f98108ab0))
- **citation:** update DOI in CITATION.cff ([ee47463](https://github.com/mchittineni/iacsecbench/commit/ee47463432da84f61344ac0642a09ec1c600a3ce))
- **workflows:** updated workflows ([78cf657](https://github.com/mchittineni/iacsecbench/commit/78cf6578db5102aaea6c70debd944ce9eda92bb6))

## 1.0.0 (2026-07-28)

### Features

- add Bayut.com-inspired Search by Commute and Regional Market Trends features ([23a05a6](https://github.com/mchittineni/iacsecbench/commit/23a05a6367f4c8571dc3f05e7dc2229bed3c5293))
- **benchmark:** expand IaCSecBench to 345 publication-grade research cases, self-contained dataset, taxonomy, leaderboard, and scoring protocol ([65edf5f](https://github.com/mchittineni/iacsecbench/commit/65edf5f2ce7dc631ef9869446e39b1a13fe6f18f))
- complete 25-year property histories across all buildings, flats, and villas in AP & TS ([fb8a85f](https://github.com/mchittineni/iacsecbench/commit/fb8a85fbd35c2d328459a140d74da2cd7d3105f4))
- expanded 25-year property sale histories for AP & TS districts ([5fcaae4](https://github.com/mchittineni/iacsecbench/commit/5fcaae476fd32d57f23e236e1db7fc221df816c2))
- **iac:** end-to-end terraform architecture, cis benchmark policies, and 100% test coverage ([706b39b](https://github.com/mchittineni/iacsecbench/commit/706b39bf310154545b4a042108c12f7d4f9ae64b))
- implement FastAPI search microservice and Typesense fast-read architecture ([e8a164e](https://github.com/mchittineni/iacsecbench/commit/e8a164ea6a43e18377286562f2c8a7b464c9ecd7))
- implement real-time real estate monitoring portal for AP & Telangana ([76c2bd0](https://github.com/mchittineni/iacsecbench/commit/76c2bd0a7ea83666e69c5a1a9f8be70cf74db7e7))
- improve insights to colony and apartment block levels ([8eee5fd](https://github.com/mchittineni/iacsecbench/commit/8eee5fda9c07e8f76116badd0f87275b0bf463a7))
- **pipeline:** add 24k statewide property history, zero-PII, hierarchical API & release workflow ([1ca88be](https://github.com/mchittineni/iacsecbench/commit/1ca88be3541a983f3b980183655f73350a23ded7))
- state-modular SRO property history, comparison tool, zero-PII compliance & repo standards ([#14](https://github.com/mchittineni/iacsecbench/issues/14)) ([e1c5a4a](https://github.com/mchittineni/iacsecbench/commit/e1c5a4afa86142d691919569291b80306e038e89))
- **workflows:** publish docs to GitHub Pages ([9117e99](https://github.com/mchittineni/iacsecbench/commit/9117e99324ce2241278be1e4610b2213e7645059))

### Bug Fixes

- **backend:** updated backend code to improve functionality and performance ([23bbdd9](https://github.com/mchittineni/iacsecbench/commit/23bbdd985093fd1b48378bbf9eef8792d83b254a))
- **backend:** updated backend to include new features and improvements ([8859bba](https://github.com/mchittineni/iacsecbench/commit/8859bba2205a104236eab2676e956b0953b99a33))
- **benchmark:** update benchmark infrastructure ([f194119](https://github.com/mchittineni/iacsecbench/commit/f1941197dfe04bc588b513a5bff324a36b3cd0c2))
- **benchmark:** update benchmark infrastructure for security audit remediation ([396cab1](https://github.com/mchittineni/iacsecbench/commit/396cab168d2ecfce127c110edddd984ff3086456))
- **benchmark:** update benchmark results ([3b64b35](https://github.com/mchittineni/iacsecbench/commit/3b64b352a516aaa3da6e9a90b51b66acc685352b))
- **benchmark:** update infrastructure for security audit remediation ([b538ec7](https://github.com/mchittineni/iacsecbench/commit/b538ec7c93236573f3dca34f5d82a75ce9698441))
- **benchmark:** updated CIS AWS Benchmark policy to address security audit findings ([3def95a](https://github.com/mchittineni/iacsecbench/commit/3def95a512ec7fd1be16ea444b7defbeb5552634))
- **ci:** add pytest-cov to requirements and setup-pipeline action; fallback --cov gracefully ([59feef1](https://github.com/mchittineni/iacsecbench/commit/59feef14df26ab941206cb5c445d7de659003260))
- **ci:** added isort black profile configuration in pyproject.toml ([dbe630b](https://github.com/mchittineni/iacsecbench/commit/dbe630b8463828e1ac6a43b3a4ef27f9fb637c1d))
- **ci:** added sys.path initialization in test_validate_iac.py and ruff ignore rules ([d1ff841](https://github.com/mchittineni/iacsecbench/commit/d1ff8410f89cef4091d73436b369193898236c8b))
- **ci:** fix conftest curl download flags and sync python formatting with black ([ff32799](https://github.com/mchittineni/iacsecbench/commit/ff3279964d319d2d09c7972da1f5f05a1a2d39d7))
- **ci:** format test_validate.py imports with isort and black ([4fe208c](https://github.com/mchittineni/iacsecbench/commit/4fe208c998dbafd319d9190c41159917599b60e0))
- **ci:** refine docs.yml workflow to verify JSDoc and upload documentation build artifact ([1fc12d9](https://github.com/mchittineni/iacsecbench/commit/1fc12d9abbf5a1d4f2ea750e7831daf4463995d7))
- **citation:** update citation file to include correct DOI and authors ([2d5e98a](https://github.com/mchittineni/iacsecbench/commit/2d5e98a0e9a255aee315205231ef0b1d59c3f992))
- **citation:** update citation file to include new authors and correct DOI ([221a781](https://github.com/mchittineni/iacsecbench/commit/221a7818350cd434e26f630dac787f6c37f9effb))
- **citation:** update CITATION.cff ([8f257fb](https://github.com/mchittineni/iacsecbench/commit/8f257fb2085a750b25f99e1f706063ca5a91806c))
- **ci:** update ci workflow to include new test steps ([5ef879c](https://github.com/mchittineni/iacsecbench/commit/5ef879c23fea41e021031cdd1998884a927ee8ed))
- **ci:** update ci.yml to include .github directory ([ca19397](https://github.com/mchittineni/iacsecbench/commit/ca193977292b2fb9705c19262a3098189b0c8d02))
- **conftest:** updated conftest to use latest version ([d1dc028](https://github.com/mchittineni/iacsecbench/commit/d1dc028d6d806db80c87591126753bd8fce2a392))
- **devops:** update CI/CD workflows to improve reliability and maintainability ([3f2bea6](https://github.com/mchittineni/iacsecbench/commit/3f2bea6dd563619769afd024cef2737782b52a9a))
- **format:** Correct format:check script in package.json ([46bffb3](https://github.com/mchittineni/iacsecbench/commit/46bffb3706aa1bf9e97f45be4319962f7058c1cb))
- **format:** fix format in changelog ([1cd10ea](https://github.com/mchittineni/iacsecbench/commit/1cd10ea6b8d2649a79d95b7de655653a94053c51))
- **formatting:** fix formatting issues ([40077d9](https://github.com/mchittineni/iacsecbench/commit/40077d9ff1c5d49676bda415b6dff6213eb4d36b))
- **iac:** update rego policy syntax to v1 for conftest compatibility ([11bf07b](https://github.com/mchittineni/iacsecbench/commit/11bf07b70efcfccb27426e97d3979a7940ee79ba))
- **lint:** update eslint config to use new rules and plugins ([a47c0a5](https://github.com/mchittineni/iacsecbench/commit/a47c0a54cb7c86fe9747db4074a94e02044cf071))
- **package:** update package-lock.json and package.json ([5f0837b](https://github.com/mchittineni/iacsecbench/commit/5f0837be20957643851567922e2bdb2e447dc7c0))
- **portal:** add fallback path resolution for geographic and market trends data files ([168d024](https://github.com/mchittineni/iacsecbench/commit/168d02479745e96c0ebed0bf40afa4125f45838c))
- **pre-commit:** resolve all pre-commit hook warnings and bandit/pylint checks ([42112db](https://github.com/mchittineni/iacsecbench/commit/42112db109fa06f3a74830852bc782d1fe81becb))
- **README:** update README with new information ([cd961b7](https://github.com/mchittineni/iacsecbench/commit/cd961b78b7f7f1395c4bffab99beea9a40abf40a))
- **release-tags:** update release-please config ([90d7f75](https://github.com/mchittineni/iacsecbench/commit/90d7f75f8c9ad62cba220e2eb887f5ffddf5bed7))
- **release:** fix release workflow to use correct branch and tag ([f8754a2](https://github.com/mchittineni/iacsecbench/commit/f8754a2f4d4f9a3e248c21e5bae070e39498ab3e))
- **script:** updated the release script to include the correct changelog path ([5e6584b](https://github.com/mchittineni/iacsecbench/commit/5e6584bf0472e036f9c0d2a907c04378913a9923))
- **security:** update security policies and configurations ([417274c](https://github.com/mchittineni/iacsecbench/commit/417274c4a19c16d68afb81fd2382cc25e9082d24))
- **sha's:** update sha's for actions to latest versions ([c8a1c72](https://github.com/mchittineni/iacsecbench/commit/c8a1c72bdce5c3fd176980bf66f379d121605202))
- **sha:** updated sha for hashicorp/setup-terraform ([7711b63](https://github.com/mchittineni/iacsecbench/commit/7711b63443d6eb9293b83ed566b27ecf516f9da6))
- **terraform:** update terraform files to address security audit findings ([0a02487](https://github.com/mchittineni/iacsecbench/commit/0a024876aec73f646842780521ff91f807beeba9))
- **terraform:** updated terraform files to fix security audit issues ([c6b69b0](https://github.com/mchittineni/iacsecbench/commit/c6b69b0f0edcf24b3a7c0a15c2e15e272607a99e))
- **workflow:** remove uptime-check workflow ([244ed66](https://github.com/mchittineni/iacsecbench/commit/244ed660a4f5b976fc567fd758c828a0bb38f622))
- **workflows:** fix release tag trigger glob and add manual trigger ([37299ce](https://github.com/mchittineni/iacsecbench/commit/37299ceff375063b13835b5010d6c2c29a77f545))
- **workflows:** force-push SRO data branches ([429d15d](https://github.com/mchittineni/iacsecbench/commit/429d15df5b4551f49f5883eeb430c7389d1343f6))
- **workflows:** handle pull request creation failure gracefully ([67a96d0](https://github.com/mchittineni/iacsecbench/commit/67a96d0cd27550d69d4890fe989adea2890510c2))
- **workflows:** resolve Scheduled Data Update and pin actions ([34edb0b](https://github.com/mchittineni/iacsecbench/commit/34edb0bb44e40fd66ad68bad96f89490b3667ce7))
- **workflows:** support manual tags in release workflow ([74f0bc4](https://github.com/mchittineni/iacsecbench/commit/74f0bc49f2970ae5a2b59eb9c3d4713d9c8d3fe2))
- **workflows:** update release.yml to parse semantic versioning tag from CHANGELOG.md (e.g. v2.0.0) ([22faef5](https://github.com/mchittineni/iacsecbench/commit/22faef5ff5343223ab38c0a5016ebf0ce352c7e7))
- **workflows:** update workflows ([4412676](https://github.com/mchittineni/iacsecbench/commit/4412676e5d932665823db2a228e550b98ef61d95))
- **workflow:** update release-please.yml ([f1ace82](https://github.com/mchittineni/iacsecbench/commit/f1ace82212b65cd513466d95c6b4f7843c6095ba))

## [1.0.0](https://github.com/mchittineni/iacsecbench/compare/iacsecbench-v1.0.0...iacsecbench-v1.0.0) (2026-07-28)

### Bug Fixes

- **citation:** update citation file to include correct DOI and authors ([2d5e98a](https://github.com/mchittineni/iacsecbench/commit/2d5e98a0e9a255aee315205231ef0b1d59c3f992))

## [1.0.0](https://github.com/mchittineni/iacsecbench/compare/iacsecbench-v1.0.0...iacsecbench-v1.0.0) (2026-07-28)

### Bug Fixes

- **benchmark:** update benchmark infrastructure ([f194119](https://github.com/mchittineni/iacsecbench/commit/f1941197dfe04bc588b513a5bff324a36b3cd0c2))
- **benchmark:** update benchmark infrastructure for security audit remediation ([396cab1](https://github.com/mchittineni/iacsecbench/commit/396cab168d2ecfce127c110edddd984ff3086456))
- **benchmark:** update benchmark results ([3b64b35](https://github.com/mchittineni/iacsecbench/commit/3b64b352a516aaa3da6e9a90b51b66acc685352b))
- **benchmark:** update infrastructure for security audit remediation ([b538ec7](https://github.com/mchittineni/iacsecbench/commit/b538ec7c93236573f3dca34f5d82a75ce9698441))
- **benchmark:** updated CIS AWS Benchmark policy to address security audit findings ([3def95a](https://github.com/mchittineni/iacsecbench/commit/3def95a512ec7fd1be16ea444b7defbeb5552634))
- **security:** update security policies and configurations ([417274c](https://github.com/mchittineni/iacsecbench/commit/417274c4a19c16d68afb81fd2382cc25e9082d24))
- **terraform:** update terraform files to address security audit findings ([0a02487](https://github.com/mchittineni/iacsecbench/commit/0a024876aec73f646842780521ff91f807beeba9))
- **terraform:** updated terraform files to fix security audit issues ([c6b69b0](https://github.com/mchittineni/iacsecbench/commit/c6b69b0f0edcf24b3a7c0a15c2e15e272607a99e))
- **citation:** update citation file to include correct DOI and authors ([2d5e98a](https://github.com/mchittineni/iacsecbench/commit/2d5e98a0e9a255aee315205231ef0b1d59c3f992))

### Security & Infrastructure Hardening

- **iac:** enforce S3 multipart upload cleanup (`abort_incomplete_multipart_upload`), CloudFront geo-restriction (whitelist `IN`), SNS topic KMS encryption, RDS deletion protection, and CloudWatch log group retention (365 days) ([706b39b](https://github.com/mchittineni/iacsecbench/commit/706b39bf310154545b4a042108c12f7d4f9ae64b))
- **iac:** align Rego CIS AWS Benchmark S3 encryption policy evaluation with decoupled Terraform provider resources ([11bf07b](https://github.com/mchittineni/iacsecbench/commit/11bf07b70efcfccb27426e97d3979a7940ee79ba))
- **ci:** configure `.checkov.yaml` and `.github/workflows/infra-ci.yml` for static analysis scanning and policy enforcement ([3f2bea6](https://github.com/mchittineni/iacsecbench/commit/3f2bea6dd563619769afd024cef2737782b52a9a))
- **tests:** resolve resource, variable, and output references across native Terraform test suites (`terraform test`) ([4fe208c](https://github.com/mchittineni/iacsecbench/commit/4fe208c998dbafd319d9190c41159917599b60e0))

### Features

- **portal:** add Bayut.com-inspired Search by Commute and Regional Market Trends features ([23a05a6](https://github.com/mchittineni/iacsecbench/commit/23a05a6367f4c8571dc3f05e7dc2229bed3c5293))
- **benchmark:** expand IaCSecBench to 345 publication-grade research cases, self-contained dataset, taxonomy, leaderboard, and scoring protocol ([65edf5f](https://github.com/mchittineni/iacsecbench/commit/65edf5f2ce7dc631ef9869446e39b1a13fe6f18f))
- **data:** complete 25-year property histories across all buildings, flats, and villas in AP & TS ([fb8a85f](https://github.com/mchittineni/iacsecbench/commit/fb8a85fbd35c2d328459a140d74da2cd7d3105f4))
- **data:** expanded 25-year property sale histories for AP & TS districts ([5fcaae4](https://github.com/mchittineni/iacsecbench/commit/5fcaae476fd32d57f23e236e1db7fc221df816c2))
- **iac:** end-to-end terraform architecture, cis benchmark policies, and 100% test coverage ([706b39b](https://github.com/mchittineni/iacsecbench/commit/706b39bf310154545b4a042108c12f7d4f9ae64b))
- **backend:** implement FastAPI search microservice and Typesense fast-read architecture ([e8a164e](https://github.com/mchittineni/iacsecbench/commit/e8a164ea6a43e18377286562f2c8a7b464c9ecd7))
- **portal:** implement real-time real estate monitoring portal for AP & Telangana ([76c2bd0](https://github.com/mchittineni/iacsecbench/commit/76c2bd0a7ea83666e69c5a1a9f8be70cf74db7e7))
- **portal:** improve insights to colony and apartment block levels ([8eee5fd](https://github.com/mchittineni/iacsecbench/commit/8eee5fda9c07e8f76116badd0f87275b0bf463a7))
- **pipeline:** add 24k statewide property history, zero-PII, hierarchical API & release workflow ([1ca88be](https://github.com/mchittineni/iacsecbench/commit/1ca88be3541a983f3b980183655f73350a23ded7))
- **data:** state-modular SRO property history, comparison tool, zero-PII compliance & repo standards ([e1c5a4a](https://github.com/mchittineni/iacsecbench/commit/e1c5a4afa86142d691919569291b80306e038e89))
- **workflows:** publish docs to GitHub Pages ([9117e99](https://github.com/mchittineni/iacsecbench/commit/9117e99324ce2241278be1e4610b2213e7645059))

### Bug Fixes

- **backend:** updated backend code to improve functionality and performance ([23bbdd9](https://github.com/mchittineni/iacsecbench/commit/23bbdd985093fd1b48378bbf9eef8792d83b254a))
- **ci:** add pytest-cov to requirements and setup-pipeline action; fallback --cov gracefully ([59feef1](https://github.com/mchittineni/iacsecbench/commit/59feef14df26ab941206cb5c445d7de659003260))
- **ci:** added isort black profile configuration in pyproject.toml ([dbe630b](https://github.com/mchittineni/iacsecbench/commit/dbe630b8463828e1ac6a43b3a4ef27f9fb637c1d))
- **ci:** added sys.path initialization in test_validate_iac.py and ruff ignore rules ([d1ff841](https://github.com/mchittineni/iacsecbench/commit/d1ff8410f89cef4091d73436b369193898236c8b))
- **ci:** fix conftest curl download flags and sync python formatting with black ([ff32799](https://github.com/mchittineni/iacsecbench/commit/ff3279964d319d2d09c7972da1f5f05a1a2d39d7))
- **ci:** format test_validate.py imports with isort and black ([4fe208c](https://github.com/mchittineni/iacsecbench/commit/4fe208c998dbafd319d9190c41159917599b60e0))
- **ci:** refine docs.yml workflow to verify JSDoc and upload documentation build artifact ([1fc12d9](https://github.com/mchittineni/iacsecbench/commit/1fc12d9abbf5a1d4f2ea750e7831daf4463995d7))
- **ci:** update ci workflow to include new test steps ([5ef879c](https://github.com/mchittineni/iacsecbench/commit/5ef879c23fea41e021031cdd1998884a927ee8ed))
- **citation:** update citation file to include correct DOI and authors ([2d5e98a](https://github.com/mchittineni/iacsecbench/commit/2d5e98a0e9a255aee315205231ef0b1d59c3f992))
- **conftest:** updated conftest to use latest version ([d1dc028](https://github.com/mchittineni/iacsecbench/commit/d1dc028d6d806db80c87591126753bd8fce2a392))
- **devops:** update CI/CD workflows to improve reliability and maintainability ([3f2bea6](https://github.com/mchittineni/iacsecbench/commit/3f2bea6dd563619769afd024cef2737782b52a9a))
- **format:** fix format in changelog ([1cd10ea](https://github.com/mchittineni/iacsecbench/commit/1cd10ea6b8d2649a79d95b7de655653a94053c51))
- **iac:** update rego policy syntax to v1 for conftest compatibility ([11bf07b](https://github.com/mchittineni/iacsecbench/commit/11bf07b70efcfccb27426e97d3979a7940ee79ba))
- **lint:** update eslint config to use new rules and plugins ([a47c0a5](https://github.com/mchittineni/iacsecbench/commit/a47c0a54cb7c86fe9747db4074a94e02044cf071))
- **portal:** add fallback path resolution for geographic and market trends data files ([168d024](https://github.com/mchittineni/iacsecbench/commit/168d02479745e96c0ebed0bf40afa4125f45838c))
- **pre-commit:** resolve all pre-commit hook warnings and bandit/pylint checks ([42112db](https://github.com/mchittineni/iacsecbench/commit/42112db109fa06f3a74830852bc782d1fe81becb))
- **README:** update README with new information ([cd961b7](https://github.com/mchittineni/iacsecbench/commit/cd961b78b7f7f1395c4bffab99beea9a40abf40a))
- **release:** fix release workflow to use correct branch and tag ([f8754a2](https://github.com/mchittineni/iacsecbench/commit/f8754a2f4d4f9a3e248c21e5bae070e39498ab3e))
- **workflows:** fix release tag trigger glob and add manual trigger ([37299ce](https://github.com/mchittineni/iacsecbench/commit/37299ceff375063b13835b5010d6c2c29a77f545))
- **workflows:** force-push SRO data branches ([429d15d](https://github.com/mchittineni/iacsecbench/commit/429d15df5b4551f49f5883eeb430c7389d1343f6))
- **workflows:** handle pull request creation failure gracefully ([67a96d0](https://github.com/mchittineni/iacsecbench/commit/67a96d0cd27550d69d4890fe989adea2890510c2))
- **workflows:** resolve Scheduled Data Update and pin actions ([34edb0b](https://github.com/mchittineni/iacsecbench/commit/34edb0bb44e40fd66ad68bad96f89490b3667ce7))
- **workflows:** support manual tags in release workflow ([74f0bc4](https://github.com/mchittineni/iacsecbench/commit/74f0bc49f2970ae5a2b59eb9c3d4713d9c8d3fe2))
- **workflows:** update release.yml to parse semantic versioning tag from CHANGELOG.md ([22faef5](https://github.com/mchittineni/iacsecbench/commit/22faef5ff5343223ab38c0a5016ebf0ce352c7e7))

### Added — Initial Release

Crown Corridor is a next-generation real-time real estate discovery and property monitoring portal for **Andhra Pradesh & Telangana**, integrated with an Open-Source IaC Security & Evaluation Benchmark Framework.

#### Web Portal (`application/app/`)

- **Live SRO Ticker** — Real-time property registration feed across all Sub-Registrar Offices in AP & TS, updating dynamically.
- **Verified Property Listings** — Geospatially verified properties (plots, flats, villas, farm land) across real AP & TS districts with detailed inquiry features.
- **Hierarchical Location Query UI** — State ➔ District ➔ Mandal / Taluk ➔ Property List location scoping across the web portal (`application/app/index.html` & `application/app/portal.js`).
- **Interactive POI Map Focus & Google Maps Directions** — `📍 Focus Map` interactive POI centering and direct `🗺️ Google Maps ↗` turn-by-turn driving directions links for all nearby infrastructure services (schools, hospitals, metro stations, parks).
- **Boundary Explorer** — Village-level LGD coordinate drill-down; vector cadastral parcel overlays via MapLibre GL.
- **Stamp Duty Calculator** — Accurate registration tax breakdown (AP 7.5%, TS 6.0%).
- **Government Guidance Value Directory** — Official SRO guide valuations by district and mandal for both states.
- **Developer API Console** — Queryable JSON sandbox and webhook alert configuration.
- **Design System** — Dark glassmorphic design system using native system typography stack for optimized legibility and performance.

#### Backend & Fast-Read API (`application/api/`)

- **Hierarchical Location API** — High-performance endpoints (`/api/v1/hierarchy/{state_code}` and `/api/v1/hierarchy/{state_code}/{district}/{mandal}/properties`) for structured geographical search.
- **Fast-Read Search & Typesense Integration** — High-throughput property search and retrieval services.

#### Research-Grade IaCSecBench Framework (`benchmark/`, `evaluation/`, `leaderboard/`, `docs/`)

- **345-Case Research Benchmark Suite** — Master catalog in `benchmark/benchmark.json` containing 345 self-contained test cases across 12 categories (`IAM`, `NET`, `STO`, `ENC`, `CMP`, `K8S`, `SRV`, `MON`, `SEC`, `ID`, `PII`, `TF`) with balanced classes (173 Pass / 172 Fail).
- **Construct Badges & Feature Metadata** — Test cases exercise advanced Terraform syntax: `dynamic_blocks`, `locals`, `for_each`, `count`, `nested_modules`, `multiple_providers`, `variable_validation`, `depends_on`, `lifecycle_rules`, `tfvars`, `opa`, `native_tests`.
- **Modular Case Architecture (`benchmark/cases/`)** — Individual self-contained case folders (`IAM-001/` through `TF-003/`) containing `main.tf`, `variables.tf`, `expected.json`, and `metadata.json`.
- **Golden Baseline Outputs (`benchmark/golden_results/`)** — Reference golden JSON outputs for Checkov, tfsec, OPA, and IaCSecBench Engine.
- **Automated Scoring Protocol (`evaluation/`)** — `evaluation/metrics.py` and `evaluation/score.py` calculating Recall, Precision, Accuracy, F1 Score, False Positive Rate (FPR), False Negative Rate (FNR), and Execution Latency.
- **Published Research Leaderboard (`leaderboard/results.csv`)** — Tabular comparative baseline matrix exported across 5 static analysis engines.
- **Research Taxonomy & Protocol Docs** — Added `docs/taxonomy.md` (5 top-level domains) and `docs/benchmark_protocol.md` (scoring methodology and reproducibility guidelines).
- **Reproducible Experiment Suite** — Integrated scoring protocol into `./experiments/run_all.sh` and `pipeline/run_experiments.py` generating telemetry in `results/` and `benchmark/reports/`.

#### Geographic Data & Zero-PII Data Pipeline (`data/`, `pipeline/`)

| State          | Districts | Mandals | Villages | Source                            |
| -------------- | --------- | ------- | -------- | --------------------------------- |
| Andhra Pradesh | 28        | 684     | 15,197   | LGD via data.gov.in (15 Jul 2026) |
| Telangana      | 33        | 616     | 9,287    | LGD via data.gov.in (15 Jul 2026) |

- **Statewide Village 25-Year Property Histories** — 24,484 property records spanning all 61 districts in TS (9,287) and AP (15,197).
- **Zero-PII Privacy Safeguards** — `sanitize_and_anonymize_record()` in `pipeline/fetch_sro.py` enforcing strict anonymized role classifications (`Private Individual Owner`, `Commercial Property Developer`, `Institutional Realty Fund`) and stripping personal identifying data.
- **Eight-Section Data Integrity Validator** — `pipeline/validate_data.py` validating required files, regions integrity, village schemas, coordinate bounding boxes, GeoJSON structures, property histories, and market trends.

#### CI/CD & Repository Infrastructure (`.github/`)

| Workflow             | Trigger                     | Purpose                                            |
| -------------------- | --------------------------- | -------------------------------------------------- |
| `ci.yml`             | Every PR → `main`           | Data validator + Ruff + ESLint + Pytest suite      |
| `infra-ci.yml`       | PR/Push to `main` (infra)   | Terraform test + Conftest OPA Rego policy checks   |
| `deploy-pages.yml`   | Push to `main`              | Data validation + publish _site to GitHub Pages    |
| `update-data.yml`    | Weekly Sun 01:00 UTC        | SRO data refresh → reviewed PR                     |
| `release-please.yml` | Merge to `main`             | Automated versioning, release PR & asset packaging |
| `uptime-check.yml`   | Every 6 hours               | Synthetic health & dataset availability checks     |
| `docs.yml`           | PR touching `app/portal.js` | JSDoc build-check                                  |

#### Documentation & Project Guidelines

- `README.md` — Full feature table, architecture layout, dev instructions, zero-PII rules, and test commands.
- `CONTRIBUTING.md`, `SECURITY.md`, `CITATION.cff` — Community health, security policy, and scientific citation metadata.

---

[1.0.0]: https://github.com/mchittineni/iacsecbench/releases/tag/v1.0.0
[releases]: https://github.com/mchittineni/iacsecbench/releases
