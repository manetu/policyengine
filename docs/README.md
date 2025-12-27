# PolicyEngine Documentation

Our documentation is built using [Docusaurus](https://docusaurus.io/), and published to [GitHub pages](https://manetu.github.io/policyengine).

## Local Development

You may start a local server of this Docusaurus site, helpful for developing the documentation.

```bash
npm install
npm start
```

Or using Make:

```bash
make start
```

Then open [http://localhost:3000/policyengine](http://localhost:3000/policyengine)

## Building the Site

To build the static site:

```bash
make build
```

This runs `npm run build` and outputs to the `build/` directory.

## Available Make Targets

### Local Development

| Target         | Description                             |
|----------------|-----------------------------------------|
| `make install` | Install npm dependencies                |
| `make build`   | Build the Docusaurus site               |
| `make start`   | Start local development server          |
| `make clean`   | Remove build artifacts and node_modules |

### Validation

| Target            | Description                                       |
|-------------------|---------------------------------------------------|
| `make lint`       | Run all validation (typecheck, spellcheck, build) |
| `make spellcheck` | Run spell checking only                           |
| `make typecheck`  | Run TypeScript type checking only                 |

### Docker Deployment

| Target                | Description                           |
|-----------------------|---------------------------------------|
| `make docker-build`   | Build the Docker image                |
| `make docker-run`     | Build and run the container           |
| `make docker-stop`    | Stop and remove the container         |
| `make docker-clean`   | Remove the container and image        |
| `make docker-logs`    | View container logs                   |
| `make docker-shell`   | Open a shell in the running container |
| `make docker-restart` | Stop and restart the container        |
| `make docker-status`  | Show container status                 |

## Docker Deployment

You can build and run the documentation site as a Docker container using nginx.

### Quick Start

```bash
make docker-run
```

This builds the Docker image and starts a container. The documentation will be available at [http://localhost:8080/policyengine/](http://localhost:8080/policyengine/)

### Configuration

You can customize the deployment using environment variables:

```bash
# Use a different port
make docker-run PORT=3000

# Custom image name and tag
make docker-build IMAGE_NAME=my-docs IMAGE_TAG=v1.0.0

# Custom container name
make docker-run CONTAINER_NAME=my-docs-container
```

| Variable         | Default             | Description         |
|------------------|---------------------|---------------------|
| `IMAGE_NAME`     | `policyengine-docs` | Docker image name   |
| `IMAGE_TAG`      | `latest`            | Docker image tag    |
| `CONTAINER_NAME` | `policyengine-docs` | Container name      |
| `PORT`           | `8080`              | Host port to expose |

## Validation

The documentation includes automated validation for broken links and spelling errors. These checks run automatically in CI on every pull request.

### Running Validation Locally

```bash
# Run all validation (typecheck, spellcheck, and build for link validation)
make lint

# Or run individual checks:
make typecheck    # TypeScript type checking
make spellcheck   # Spell checking only
make build        # Build (also validates links and anchors)
```

### Validation Checks

| Check           | Description                                                               |
|-----------------|---------------------------------------------------------------------------|
| TypeScript      | Validates TypeScript configuration and types                              |
| Spell Check     | Checks spelling in all markdown files using [cspell](https://cspell.org/) |
| Link Validation | Docusaurus build validates all internal links and anchors                 |

### Spell Checking

The spell checker uses [cspell](https://cspell.org/) with a custom dictionary for project-specific terms.

**Adding words to the dictionary:**

Edit `cspell.json` and add the word to the `words` array:

```json
{
  "words": [
    "ExistingTerm",
    "YourNewTerm"
  ]
}
```

**Inline exceptions:**

You can disable spell checking for specific lines or sections:

```markdown
<!-- cspell:disable-next-line -->
This line contains UnusualTermThatShouldNotBeChecked.

<!-- cspell:disable -->
This entire section will not be spell checked.
Multiple lines can be skipped.
<!-- cspell:enable -->

<!-- cspell:ignore someword anotherword -->
This line ignores someword and anotherword only.
```

**Adding words inline:**

```markdown
<!-- cspell:words MyCustomWord AnotherWord -->
Now MyCustomWord and AnotherWord are valid in this file.
```
