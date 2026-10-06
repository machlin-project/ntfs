# Diagram sources

These Mermaid sources are original illustrations for the NTFS format reference.
The neighbouring SVGs are rendered documentation assets so Markdown readers do
not need a Mermaid runtime, network access or a browser extension. Chapters link
both the illustration and its editable source.

Use the shared [theme](theme.json) and Mermaid CLI to render a changed source
from the NTFS repository's working directory, for example:

```sh
mmdc -i docs/format/diagrams/overview.mmd \
     -o docs/format/diagrams/overview.svg \
     --configFile docs/format/diagrams/theme.json \
     --backgroundColor white
```

Use a task-local headless browser configuration if the renderer needs an
explicit browser executable. Rendered PNG previews and command logs belong in
ignored build/artifact state. Inspect the changed diagram for clipped labels,
legible text, arrow direction and agreement with its chapter before retaining
the SVG. Do not add tool downloads or browser profiles to source history.

Mermaid's [flowchart syntax](https://mermaid.js.org/syntax/flowchart.html) is the
renderer reference. Mermaid rendering establishes syntax and presentation;
NTFS relationships still need the source and evidence described by the chapter.
