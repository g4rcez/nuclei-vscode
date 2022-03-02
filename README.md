# Nuclei Vscode

Support autocomplete for [Nuclei](https://nuclei.projectdiscovery.io/) Templates.

### Install

[Marketplace link](https://marketplace.visualstudio.com/items?itemName=g4rcez.nuclei-vscode)

```bash
# Press CTRL+P in your vscode
ext install g4rcez.nuclei-vscode
```

### Configure

You can configure filename patterns to match as `nuclei-vscode` language.

```json
"files.associations": {
    // ...
    "*.template.yaml": "nuclei-vscode",
    "*.template.yml": "nuclei-vscode",
    // ...
},
```

or, you can just enable manually:

```
> Ctrl + Shift + P
> Change Language Mode
> Nuclei Vscode (nuclei-vscode)
```

### Schema support

- **id**: url friendly regex. Not nuclei default regex for ID
- **Info**
  - classification (object)
  - severity (enum)
- **Requests**
  - method (enum)
  - attack (enum)
- **Dns**
  - class (enum)
  - type (enum)
- **File**
- **Network**
- **Headless**
- **SSL**
- **WebSocket**
- **Matchers**

### ToDo

- [x] Support for DNS
- [x] Support for File
- [x] Support for Network
- [x] Support for Headless
- [x] Support for SSL
- [x] Support for WebSocket
- [x] Matchers support (stop-at-first-match)
- Add tests for templates using templates from [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)

### Thanks

This project was forked from the [Azure Pipelines Vscode](https://github.com/microsoft/azure-pipelines-vscode)
