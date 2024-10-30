# Demo Hello World App repo using GitHub Artifact Attestations

- [Quick Start Guide](#quick-start-guide)
- [Paving the Path](#paving-the-path)
- [Usage](#usage)
  - [GitHub Artifact Attestation Actions and Other Tools Used](#github-artifact-attestation-actions-and-other-tools-used)
  - [Configure Access](#access)
  - [Inputs](#inputs)
  - [Outputs](#outputs)
  - [Example Workflow Snippets](#example-workflow-snippets)
- [Troubleshooting](#troubleshooting)
- [Additional Resources/Documentation](#additional-resourcesdocumentation)

## Purpose

This repo serves as a demo app for running Automated Governance workflows and render the autogov results in a Backstage instance.

👉 [Visit Our Contact Page](https://www.liatrio.com/) for more information on how Liatrio can support your Backstage or Automated Governance journey.

This repo is meant to be publicly visible.

This repo **must** be set to internal when in development because it calls an internally visible reusable workflow and GitHub does not yet support calling a private or internal workflow from a public repo.

## Quick Start Guide

1. **Configure Access**:
   Ensure you have the necessary permissions and tokens configured in your remote caller repository described in the [access section](#access) below.
   - **Permissions**: Ensure you have the [necessary permissions to run the workflows](#workflow-access).
   - **Tokens**: Set up the [required tokens](#repository-access) for repo access.
2. **Create Your Local Composite Actions**:
   For example create `.github/actions/build-image/action.yaml` for images or `.github/actions/build-blob/action.yaml` for blobs:

**`build-image`Composite Action**

```yaml
inputs:
  subject-name:
    description: The name for the image.
    required: true
    default: ghcr.io/${{ github.repository }}
  use-low-perms:
    description: >
      Primarily for demo purposes and specific only to the build-image composite action so that it is unnecessary to manually change it when wanting to flip from high permissions to low permissions.
    default: "false"
    required: false
outputs:
  image-digest:
    description: The image digest of the image that was built from the build-image job.
    value: ${{ steps.build-image.outputs.digest }}

runs:
  using: composite
  steps:
    - name: Image Metadata
      id: meta
      uses: docker/metadata-action@8e5442c4ef9f78752691e2d8f8d19755c6f78e81 # v5.5.1
      with:
        images: ${{ inputs.subject-name }}
        tags: |
          type=ref,event=branch
          type=sha
          type=raw,value=latest,enable=${{ github.event_name == 'release' }}
          type=raw,value=${{ github.event.release.tag_name }},enable=${{ github.event_name == 'release' }}
    - name: Set up QEMU
      uses: docker/setup-qemu-action@49b3bc8e6bdd4a60e6116a5414239cba5943d3cf # v3.2.0
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@c47758b77c9736f4b2ef4073d4d51994fabfe349 # v3.7.1
    - name: Log in to GitHub Container Registry
      uses: docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567 # v3.3.0
      with:
        registry: ghcr.io
        username: ${{ github.actor }}
        password: ${{ github.token }}
    - name: Build and push Docker image
      uses: docker/build-push-action@4f58ea79222b3b9dc2c8bbdd6debcef730109a75 # v6.9.0
      id: build-image
      with:
        context: .
        file: Dockerfile
        push: ${{ inputs.use-low-perms == 'false' && 'true' || inputs.use-low-perms == 'true' && 'false' }}
        platforms: linux/amd64,linux/arm64
        tags: ${{ steps.meta.outputs.tags }}
        labels: ${{ steps.meta.outputs.labels }}
        outputs: type=oci,dest=/tmp/image.tar
        cache-from: type=gha
        cache-to: type=gha,mode=max
```

1. **Create Your Caller Workflows / Configure Inputs**:

**`cw-build-image.yaml`**:

### Calling Reuseable Workflow

```yaml
name: Build Entrypoint Caller Workflow

on:
  workflow_dispatch:
  release:
    types: [published]
  push:
    branches: ["**"]

permissions: {}

jobs:
  attest-image-hp: #image
    permissions:
      id-token: write
      attestations: write
      packages: write
      contents: write
    uses: liatrio/demo-gh-autogov-workflows/.github/workflows/rw-hp-build-image.yaml@7031b13fe73cb32c5ab0897d12fb4db3e9a4fea7 # v0.13.0
    secrets: inherit
    with:
      subject-name: ghcr.io/${{ github.repository }}
      cert-identity: https://github.com/liatrio/demo-gh-autogov-workflows/.github/workflows/rw-hp-attest-image.yaml@7031b13fe73cb32c5ab0897d12fb4db3e9a4fea7 # v0.13.0
```

4. **Run the Workflow**:
   Trigger the workflow using one of the supported event types:

    - [`push`] / [creation or update of a git tag or branch](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#create).
    - [`release`] / [creation or update of a GitHub release](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#release).
    - [`create`] / [creation of a git tag or branch](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#push).
    - [`workflow_dispatch`] / [enables the ability to trigger workflow manually](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#workflow_dispatch).

5. **Check Results**:
   Review the results and logs to ensure everything is working as expected.

## Why Sign/Attest?

In today's digital landscape, ensuring the integrity and security of software development processes is crucial. GitHub's official Action(s) for creating signed SLSA (Supply Chain Levels for Software Artifacts) attestations, along with its [CLI tool for verifying artifacts](https://cli.github.com/manual/gh_attestation), provides a robust foundation for securing the distribution of built artifacts.

SLSA is a security framework designed to prevent tampering, improve integrity, and secure packages and infrastructure. It provides a checklist of standards and controls to enhance software supply chain security. For more details, visit the [SLSA website](https://slsa.dev/).

To achieve [SLSA Build Level 3](https://slsa.dev/spec/v1.0/levels#build-l3), which mitigates risks such as:

- Running builds on self-hosted runners
- Unapproved code changes
- Exposed credentials associated with attestation signing material
- [Hard-to-follow build steps](https://slsa.dev/spec/v1.0/provenance#BuildDefinition)

GitHub recommends using [reusable workflows](https://github.com/slsa-framework/github-actions-buildtypes/tree/main/workflow/v1).

This README outlines how our services can help your organization implement a Reusable Workflow to meet SLSA Build Level 3 requirements, ensuring a secure and compliant Software Development Life Cycle (SDLC).

By implementing this reusable workflow, your organization can achieve SLSA Build Level 3 compliance, ensuring a secure and verifiable software development process. Our team is ready to assist you in integrating these automated governance technologies into your SDLC, enhancing the security and integrity of your software artifacts.

### GitHub Artifact Attestations

GitHub Artifact Attestations is a feature that enables developers to generate cryptographically signed attestations that verify the provenance of software artifacts created during CI/CD pipelines. These attestations are based on the Open Container Initiative (OCI) format and follow the SLSA (Supply Chain Levels for Software Artifacts) framework, but can also work against blob or files. Attestations provide verifiable metadata about how, when, and by whom an artifact was built, ensuring integrity and preventing tampering.

By using any of GitHub's attest Actions, developers can automate the creation of attestations directly in their pipelines. These attestations are signed and associated with build artifacts, which can then be stored in OCI-compliant registries. The signatures can be verified using GitHub's own tools or [external tools like Sigstore's `cosign`](https://blog.sigstore.dev/cosign-verify-bundles/), ensuring that any unauthorized changes or modifications to the artifact can be detected.

This offering is now generally available, as announced in June 2024, with public repositories using Sigstore’s public instance for signing, while private repositories are backed by GitHub’s private Sigstore instance. This ensures that all repositories can integrate artifact attestations into their workflows while maintaining the same level of cryptographic security.

For more information, visit the [GitHub documentation on artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds).

### The SLSA Build Track

There are a variety of necessary checkboxes ✅ required to achieve different SLSA Build Levels on the SLSA [build track](https://slsa.dev/spec/v1.0/levels#build-track), which sets expectations for achieving each Build Level without assumptions.

For build provenance attestation, "the lowest level only requires the provenance to exist, while higher levels provide increasing protection against tampering of the build, the provenance, or the artifact." It is specifically through the verification process that it is confirmed that they were "built as expected," preventing a variety of [supply chain threats](https://slsa.dev/spec/v1.0/threats).

#### Build Level 1: Provenance showing how and who built the artifact

- Provenance Generation
  - Ensure that the provenance includes detailed metadata about the build process, such as the build system, input sources, and dependencies.

- No Strong Security Guarantees
  - About establishing a baseline for tracking and does not yet enforce strong security measures.

#### Build Level 2: Built on Hosted Platform

- Hosted Build Platform
  - Emphasize the importance of using a trusted service provider to manage the build environment.

- Scripted Builds
  - Ensure that all build processes are fully scripted and reproducible to prevent unauthorized changes.

- Immutability
  - Specify that inputs, like dependencies, should be locked to specific versions or commit hashes to ensure consistency.

#### Build Level 3: Hardened build platform

- Hardened build platform
  - Focus on the isolation between builder and signer environments to prevent tampering.

- Non-falsifiable provenance
  - Ensure that provenance is cryptographically signed to guarantee its integrity and authenticity.

- Automated enforcement
  - Highlight the importance of automation in reducing human error and insider risks.

## Sigstore

Sigstore is an open-source project that aims to improve the security of the software supply chain by providing a set of tools for signing, verifying, and storing software artifacts. It includes several key components:

- **Rekor**: A transparency log that records signed metadata, providing an immutable and publicly auditable record of software artifacts and their provenance. This helps ensure that the artifacts have not been tampered with and can be traced back to their source. For more details, visit the [Rekor GitHub repository](https://github.com/sigstore/rekor).
- **Fulcio**: A certificate authority that issues short-lived certificates based on OpenID Connect (OIDC) identities. This allows for "keyless" signing, where the private key is ephemeral and never leaves the memory of the signing process. For more details, visit the [Fulcio GitHub repository](https://github.com/sigstore/fulcio).
- **Cosign**: A tool for signing and verifying container images and other artifacts. It integrates with Fulcio and Rekor to provide a seamless signing and verification experience. For more details, visit the [Cosign GitHub repository](https://github.com/sigstore/cosign).

GitHub's artifact attestation feature leverages Sigstore using GitHub's own private Sigstore instance (e.g. private repositories use their private instance and public repositories utilize Sigstore's public good instance) to create a verifiable link between software artifacts and their source code and build instructions. By using GitHub Actions, developers can easily generate and verify signed attestations, ensuring the integrity and security of their software supply chain.

For more details, you can refer to the [GitHub blog post](https://github.blog/news-insights/product-news/introducing-artifact-attestations-now-in-public-beta/) and the [Sigstore blog](https://blog.sigstore.dev/cosign-verify-bundles/). Additionally, the [Cosign GitHub repository](https://github.com/sigstore/cosign) provides comprehensive documentation and examples.

### Paving the Path

To achieve SLSA Build Level 3, we recommend using GitHub-native tools and reusable workflows. Our approach is inspired by the slsa-framework's implementations, specifically [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator/blob/main/BYOB.md#build-your-own-builder-byob-framework) and [slsa-verifier](https://github.com/slsa-framework/slsa-verifier), and provides a model for securing your software development process.

["The only way to interact with a reusable workflow is through the input parameters it exposes to the calling workflow."](https://github.com/slsa-framework/slsa-github-generator/blob/3d34abbe34b268bb6c02651df2117370e8cee1bd/SPECIFICATIONS.md#interference-between-jobs)

```shell
                    ┌──────────────────────┐         ┌───────────────────────────────┐
                    │                      │         │                               │
                    │  Source Repository   │         │       Trusted Builder         │
                    │  -----------------   │         │     (Reusable Workflow)       │
                    │                      │         │     -------------------       │
                    │                      │         │                               │
                    │ .caller-workflow.yaml│         │                               │
                    │                      ├─────────┼─────────────┐                 │
                    │                      │         │             │                 │
                    │                      │         │   ┌─────────▼────────────┐    │
                    │   User Workflow      │         │   │     Build            │    │
                    │                      │         │   └──────────────────────┘    │
                    └──────────────────────┘         │             │                 │
                                                     │   ┌─────────▼────────────┐    │
                                                     │   │  Generate Provenance │    │
                                                     │   └─────────┬────────────┘    │
                                                     │             │                 │
                                                     └─────────────┼─────────────────┘
                                                                   │
                                                                   │
                                                     ┌─────────────▼─────────────────┐
                                                     │                               │
                                                     │   Binary    Signed Provenance │
                                                     │                               │
                                                     │                               │
                                                     │         Artifacts             │
                                                     │         ---------             │
                                                     └───────────────────────────────┘
```

This diagram illustrates the process of using a reusable workflow to achieve SLSA Build Level 3. The source repository contains the caller workflow, which interacts with the trusted builder (reusable workflow) to build the artifacts and generate signed provenance. The artifacts and their signed provenance are then securely stored and can be verified to ensure their integrity.

## Filling-in the gaps to Achieve SLSA Build Levels with GitHub Artifact Attestations

1. **Verification of Artifacts**:
   - Emphasize the importance of verifying artifacts to ensure their integrity and authenticity across all SLSA levels.
   - Utilize GitHub's `gh attestation verify` command to validate that both the source repository and signer workflow originate from approved branches or tags.
   - Implement additional checks using `jq` and `grep` to ensure compliance with SLSA Level 3 requirements, addressing the current limitations of GitHub's CLI.
   - [Learn more about verifying artifacts](https://slsa.dev/spec/v1.0/verifying-artifacts).

2. **Isolation of Build and Attestation Processes**:
   - For SLSA Level 3, the emphasis is on separate build and attestation processes into distinct jobs to prevent inadvertent or malicious alterations.
     - [Using reuseable workflows](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-and-reusable-workflows-to-achieve-slsa-v1-build-level-3) helps to achieve this by isolating the build process from the calling workflow.
     - [Understand the importance of job isolation](https://slsa.dev/spec/v1.0/levels#build-l3-hardened-builds).

3. **Artifact Management**:
   - Use immutable uploads and secure downloads to manage artifacts between jobs, crucial for maintaining integrity at all levels.
      - Employ temporary solutions, such as using `actions/github-script` with `@actions/artifact`, to handle limitations in GitHub's current artifact management capabilities.
      - [Explore GitHub's artifact management](https://github.com/actions/upload-artifact).

4. **Permission Management**:
   - Minimize permissions required for workflows, especially for image builds, by using fine-grained access controls.
      - Handle image artifacts as tar files to pass data between jobs securely, reducing the need for additional permissions.
      - [Read about permission management](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions).

5. **Ensuring a Trusted Build Environment**:
   - Use GitHub-hosted runners to maintain the integrity of the build environment, a requirement for SLSA Level 2 and above.
      - Ensure jobs run on GitHub's hardened runners to maintain a secure execution environment, avoiding self-hosted runners, which could be compromised.
      - [Learn more about trusted build environments](https://slsa.dev/spec/v1.0/levels#build-l2-hosted-build-platform).

6. **Documented Build Parameters**:
   - Ensure consistent and verifiable build steps to meet SLSA Level 1 requirements.
      - Document and attest to workflow inputs to prevent script injection attacks, using custom predicates to include user inputs.
      - [Understand the importance of documenting build parameters](https://slsa.dev/spec/v1.0/provenance#BuildDefinition).

7. **Challenges with Pull Request Events**:
   - Avoid supporting pull request events due to potential security risks from untrusted sources.
      - Consider ongoing strategies for handling such events securely, ensuring workflows are executed in a controlled environment.
      - [Explore the challenges with pull request events](https://github.com/slsa-framework/slsa-github-generator/issues/358).

These points provide a comprehensive overview of the efforts and considerations involved in achieving various SLSA Build Levels using GitHub's offerings, focusing on security, verification, and compliance. For more details, visit the [SLSA website](https://slsa.dev/).

## Usage

### GitHub Artifact Attestation Actions and Other Tools Used

#### Build Provenance GitHub Action

- [Attest Build Provenance Action](https://github.com/actions/attest-build-provenance)

We use the [actions/attest-build-provenance](https://github.com/actions/attest-build-provenance) GitHub Action to generate build provenance attestations for workflow artifacts. This action binds a named artifact along with its digest to a SLSA build provenance predicate using the in-toto format.

#### Attest SBOM Action

- [Attest SBOM Action](https://github.com/actions/attest-sbom)

We use the [anchore/sbom-action](https://github.com/anchore/sbom-action) GitHub Action to create a software bill of materials (SBOM) using Syft. This action scans your artifacts and generates an SBOM in various formats, which can be uploaded as workflow artifacts or release assets.

#### Cosign Generic Predicate

- [Attest Action](https://github.com/actions/attest)

We use the [actions/attest](https://github.com/actions/attest) GitHub Action to generate attestations for pipeline metadata, or any other metadata, to attest to a particular event/artifact using the [cosign generic predicate](https://github.com/sigstore/cosign/blob/main/specs/COSIGN_PREDICATE_SPEC.md) which is [a simple, generic, format for data that doesn't fit well into other types](https://docs.sigstore.dev/system_config/specifications/#in-toto-attestation-predicate).

#### GitHub CLI Attestation Commands

We use the `gh attestation` commands from the [GitHub CLI](https://cli.github.com/manual/gh_attestation) to manage artifact attestations. These commands allow us to:

- **Verify Attestations**: Ensure the integrity and authenticity of artifacts by verifying their attestations. This can be done both online and offline, providing flexibility in different environments.
- **Download Attestations**: Retrieve attestations for artifacts, which can then be used for further verification or auditing purposes.

#### OCI Artifacts

The Open Container Initiative (OCI) is an open governance structure for creating open industry standards around container formats and runtimes. For more information, visit the [Open Container Initiative website](https://opencontainers.org/).

The attest GitHub Actions effectively "sign" the images with OCI artifact attestations linking the image to a specific workflow run that built it and has the necessary metadata (e.g. source repo, commit SHA, etc ) to prove/attest to provenance (or SBOM, metadata, test-result) is legitimate.

There are three clues as to whether you are dealing with OCI artifacts in a workflow specifically for high permission image builds:

- The GitHub Action that is part of the workflow pushes an image (e.g. `push-to-registry` is `true`)
- `permissions.packages.read/write` exists
- Any `oci://` URIs whereby we write and pull attestation data to and from GitHub Container Registry (e.g. using the GitHub CLI)

##### Significance of OCI Format vs Docker Format

Within the workflow you will notice a section for the `build-image` step that defines the type or format for the image output. The Docker format can sometimes cause errors especially when exporting multi-platform images (e.g. `docker exporter does not support exporting manifest lists`), which pushes others to the OCI format which is more standardized and compatible across various container runtimes (e.g., Docker, Kubernetes).

##### Other Ways to Inspect and Download Image Attestations

Using Docker we can interact and inspect the attestations that have been attached to our container images:

```bash
❯ docker manifest inspect ghcr.io/<repo>@<image_digest>
```

```json
{
   "schemaVersion": 2,
   "mediaType": "application/vnd.oci.image.index.v1+json",
   "manifests": [
      {
         "mediaType": "application/vnd.oci.image.manifest.v1+json",
         "size": 2005,
         "digest": "sha256:<sha_digest>",
         "platform": {
            "architecture": "amd64",
            "os": "linux"
         }
      },
...
      {
         "mediaType": "application/vnd.oci.image.manifest.v1+json",
         "size": 566,
         "digest": "sha256:<sha_digest>",
         "platform": {
            "architecture": "unknown",
            "os": "unknown"
         }
      }
   ]
}
```

From there, you can continue to drill into each attestation by inspecting each respective sha256 digest finding the type of attestation (e.g. `application/vnd.in-toto+json`):

### Limiting Inputs by Wrapping Reuseable Workflow Calls in an Additional Workflow Layer

It is good practice to wrap the actual call to each respective reuseable workflow in an additional reuseable workflow layer to limit the amount of inputs the user has access to (e.g. inputs for the verify and/or opa eval jobs) which helps to circumvent script injection attacks.

### Access

#### Workflow Access

[Explicit workflow permissions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#allowing-select-actions-and-reusable-workflows-to-run) can be set to only alllow the "entrypoint" reuseable workflows that call other reuseable workflows.

Below are all of the GitHub Actions and Workflows that are permitted access in the caller workflow repo. The only reuseable workflows not given direct access are `rw-<permissions_path>-attest-<build_type>.yaml`, `rw-<permissions_path>-verify.yaml`, `rw-<permissions_path>-run-opa.yaml`, and `rw-<permissions_path>-release.yaml`:

```yaml
actions/attest-build-provenance/predicate@*,
actions/attest-build-provenance@*,
actions/attest-sbom/predicate@*,
actions/attest-sbom@*,
actions/attest@*,
actions/checkout@*,
actions/delete-package-versions@*,
actions/github-script@*,
actions/upload-artifact@*,
anchore/sbom-action@*,
docker/build-push-action@*,
docker/login-action@*,
docker/metadata-action@*,
docker/setup-buildx-action@*,
docker/setup-qemu-action@*,
go-semantic-release/action@*,
open-policy-agent/setup-opa@*,
softprops/action-gh-release@*,
liatrio/demo-gh-autogov-workflows/.github/workflows/rw-hp-build-blob.yaml@*,
liatrio/demo-gh-autogov-workflows/.github/workflows/rw-hp-build-image.yaml@*,
liatrio/demo-gh-autogov-workflows/.github/workflows/rw-lp-build-blob.yaml@*,
liatrio/demo-gh-autogov-workflows/.github/workflows/rw-lp-build-image.yaml@*,
```

#### Repository Access

Required token permissions for access to the following private repositories:

A [fine grained personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) especially if code repositories are owned by an organization. As mentioned in the Quick Start Guide, be sure to include the necessary token [in the Secrets and Variables section for Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions).

`RW_CW_POLICY_REPO_ACCESS`:

- `Actions`
  - read
- `Contents`
  - read
  - write
- `Metadata`
  - read
- `Workflows`
  - read
  - write

### Inputs

#### `.github/actions/build-image/action.yaml`

- `subject-name` (required, string, default: 'ghcr.io/${{ github.repository }}'): Subject name as it should appear in the attestation.
- `use-low-perms` (optional, boolean, default: false): Enables / Disables push to registry for the composite action; more for demo purposes.

#### `.github/workflows/rw-hp-build-image.yaml`

- `subject-name` (required, string): Subject name as it should appear in the attestation.
- `use-low-perms` (optional, boolean, default: false): Primarily for demo purposes and specific only to the build-image composite action so that it is unnecessary to manually change it when wanting to flip from high permissions to low permissions.
- `cert-identity` (required, string): The certificate identity of the signer workflow, or builder, used in the verify job to ensure artifacts and attestations can be verified against the source repository and correct workflow using the gh-cli (e.g. --cert-identity flag). If verifying an image, the workflow name should be rw-<permissions_path>-attest-image.yaml, if verifying blob(s), the workflow name should be rw-<permissions_path>-attest-blob.yaml

### Outputs

#### `.github/workflows/rw-hp-build-image.yaml`

- No outputs for this action

#### `.github/workflows/rw-lp-build-image.yaml`

- No outputs for this action

#### `.github/actions/build-image/action.yaml`

- `image-digest` (string): The image digest of the image that was built from the build-image job.

## Troubleshooting

### Common Issues

1. **Permission Denied**:
   Ensure that your PAT and respective workflows have the necessary [access](#access sections).

2. **Workflow Fails to Trigger**:
   Check that you are using one of the supported event types: `create`, `release`, `push`, or `workflow_dispatch`.

3. **Attestation Verification Fails**:
   Ensure that the `cert-identity` and other inputs are correctly specified. Verify that the workflow is running on GitHub-hosted runners.

The following can be helpful to troubleshoot GitHub environment variables; often used for things such as the owner and repository:

```yaml
- name: DEBUG THE THINGS
  shell: bash
  env:
    GITHUB_CONTEXT: ${{ toJson(github) }}
    JOB_CONTEXT: ${{ toJson(job) }}
    STEPS_CONTEXT: ${{ toJson(steps) }}
    RUNNER_CONTEXT: ${{ toJson(runner) }}
    INPUTS_CONTEXT: ${{ toJson(runner) }}
  run: |
    echo "$GITHUB_CONTEXT"
    echo "$JOB_CONTEXT"
    echo "$STEPS_CONTEXT"
    echo "$RUNNER_CONTEXT"
    echo "$INPUTS_CONTEXT"
- name: Show default environment variables
  shell: bash
  run: |
    echo "The job_id is: $GITHUB_JOB"
    echo "The id of this action is: $GITHUB_ACTION"
    echo "The run id is: $GITHUB_RUN_ID"
    echo "The GitHub Actor's username is: $GITHUB_ACTOR"
    echo "GitHub SHA: $GITHUB_SHA"
- name: List all GitHub environment variables
  shell: bash
  run: printenv | grep '^GITHUB_'
```


## Additional Resources/Documentation

- [Why is Github Artifact Attestations Considered SLSA Build L2+ and not SLSA Build L3?](https://www.ianlewis.org/en/understanding-github-artifact-attestations)
- [Trusted Builder and Provenance Generator Specifications](https://github.com/slsa-framework/slsa-github-generator/blob/3d34abbe34b268bb6c02651df2117370e8cee1bd/SPECIFICATIONS.md#trusted-builder-and-provenance-generator)
- [Hardening Requirements](https://github.com/slsa-framework/slsa-github-generator/blob/main/BYOB.md#hardening)
- [Best SDLC Practices](https://github.com/slsa-framework/slsa-github-generator/blob/main/BYOB.md#best-sdlc-practices)
- [Build Your Own Builder (BYOB) Framework](https://github.com/slsa-framework/slsa-github-generator/blob/main/BYOB.md#build-your-own-builder-byob-framework)
- [Provenance Build Definition](https://slsa.dev/spec/v1.0/provenance#BuildDefinition)
- [Provenance Model/Schema](https://slsa.dev/spec/v1.0/provenance#model)
