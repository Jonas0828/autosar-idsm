#!/usr/bin/env python3
"""Extract text (paragraphs + tables) from a .docx without external deps."""
import io
import sys
import zipfile
import xml.etree.ElementTree as ET

W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'


def text_of_paragraph(p):
    parts = []
    for node in p.iter():
        if node.tag == W + 't' and node.text:
            parts.append(node.text)
        elif node.tag == W + 'tab':
            parts.append('\t')
        elif node.tag == W + 'br':
            parts.append('\n')
    return ''.join(parts)


def walk(elem, out, depth=0):
    for child in elem:
        if child.tag == W + 'p':
            t = text_of_paragraph(child)
            out.append(t)
        elif child.tag == W + 'tbl':
            out.append('---- TABLE ----')
            for row in child.findall(W + 'tr'):
                cells = []
                for tc in row.findall(W + 'tc'):
                    ct = []
                    for p in tc.iter(W + 'p'):
                        ct.append(text_of_paragraph(p))
                    cells.append(' '.join(x for x in ct if x).strip())
                out.append(' | '.join(cells))
            out.append('---- END TABLE ----')
        else:
            walk(child, out, depth + 1)


def main():
    src, dst = sys.argv[1], sys.argv[2]
    z = zipfile.ZipFile(src)
    xml = z.read('word/document.xml')
    root = ET.fromstring(xml)
    body = root.find(W + 'body')
    out = []
    walk(body, out)
    text = '\n'.join(out)
    io.open(dst, 'w', encoding='utf-8').write(text)
    print(f'{len(text)} chars -> {dst}')


if __name__ == '__main__':
    main()
