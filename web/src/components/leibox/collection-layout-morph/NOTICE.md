# LeiBox source and adaptation notice

Component: collection-layout-morph (React)
Source: https://leibox.pantoria.cn/docs/animations/collection-layout-morph
Design reference: https://x.com/shawn_kel/status/2087937950424129978/video/1
Design author: Previous Leon

Original layout/code license not supplied or independently verified; original illustrations and reference video are not redistributed. Reused existing Claude/Codex vectors retain Lobe Icons Copyright (c) 2023 LobeHub and MIT notice. Grok Bot artwork source is recorded separately without claiming an MIT license for it.

Nexo adaptation: native application DOM and existing state replace the fixed demonstration stage. Demo fonts, images, SVG artwork, and the generic demonstration surface runtime are not included. Source attribution is preserved; no MIT or Nexo AGPL license is claimed for the upstream component.

## Original asset provenance (assets removed from Nexo adaptation)

The following upstream notice is retained verbatim as a source record, not a claim that its license applies to the component code.

```text
/*! SVG sources and notice
# Inline morph SVG assets

Retrieved on 2026-10-25. Pinned source files are stored beside this document.

- `codex-color.svg`: https://raw.githubusercontent.com/lobehub/lobe-icons/master/packages/static-svg/icons/codex-color.svg — Lobe Icons, Copyright (c) 2023 LobeHub, MIT. The importer preserves the original cloud path and gradient, removes the app tile, and adds a white sticker outline. The reference labels this icon “ChatGPT”; that label is retained.
- `claude-color.svg`: https://www.graphicalui.com/marketing/agents/claude-color.svg — the exact sticker SVG used by the reference page. The underlying path matches Lobe Icons' `claude-color.svg`; the reference adds a white outline.
- `cursor.svg`: https://www.graphicalui.com/marketing/agents/cursor.svg — the exact sticker SVG used by the reference page. The underlying path matches Lobe Icons' `cursor.svg`; the reference adds a white outline.
- `grok-bot.svg`: https://www.graphicalui.com/marketing/agents/grok.svg — the exact Grok Bot sticker SVG used by the reference page; it is distinct from Grok's swoosh logomark. No separate artwork license was supplied with this asset.

Lobe Icons repository: https://github.com/lobehub/lobe-icons
Full MIT notice: `LICENSE` in this directory. That notice covers Lobe Icons' code and vector contributions; brand marks remain their respective owners' trademarks. Graphical's design and additional artwork license is not independently verified.

`scripts/import-inline-agent-icons.mjs` converts these pinned files into `src/data/inline-agent-icons.mjs`; it does not redraw their paths. Generated component bundles retain this record and the MIT notice. The other feature stickers remain local reconstructions.

## Corrected feature SVGs

The themes and spacing shapes in `src/data/inline-text-morph.mjs` adapt the reference page's public inline SVG geometry, observed in https://www.graphicalui.com/ and its JavaScript artwork module `10ysidpnhxe89.js` retrieved with the reference evidence. Themes retains the original card dimensions, colours, and back-to-front paint order. Spacing retains the original rounded ruler shape, tick path, white outline, and `paint-order="stroke fill"`. Their overall rotations remain the local replica's measured angles. Other feature stickers remain local reconstructions. These two reference SVGs have no separately verified artwork license; the Lobe Icons MIT notice does not grant a license for them.

MIT License

Copyright (c) 2023 LobeHub

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/
```
