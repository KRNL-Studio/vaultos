// Writes the cases the Rust core's .env parser is checked against: inputs and what the
// `dotenv` package (which this app uses to import) makes of them. Synthetic values only.
// Run: node scripts/make-dotenv-fixture.mjs

import { createRequire } from "node:module";

import { writeFileSync } from "node:fs";

import path from "node:path";

const require = createRequire(import.meta.url);

const dotenv = require("dotenv");

const inputs = [
    "A=1\nB=two\n",
    "export A=1\nexport  B = spaced \n",
    "A = 1 # comment\nB=1#not-a-comment\nC='x # y'\nD=\"x # y\" # c\n",
    "A='single'\nB=\"double\"\nC=`back`\nD='unterminated\nE=\"mixed'\n",
    "A=\"line\\nbreak\"\nB='line\\nkept'\nC=\"tab\\tkept\"\nD=\"cr\\rx\"\n",
    "A=\"multi\nline\nvalue\"\nB='also\nmulti'\nC=`and\nthis`\n",
    "A=\nB= \nC=''\nD=\"\"\nE\nF=a=b=c\n",
    "a.b=dots\nc-d=dashes\nE:colon\n_F=under\n9G=digit\n",
    "K=a\r\nL=b\r\nM=c",
    "K=a\rL=b",
    "2=b\n1=a\nZ=z\n1=again\n10=ten\n01=lead\n",
    "﻿BOM=first\nX= nbsp \n",
    "  INDENT=yes\n\tTAB=yes\n# full comment\n   # indented comment\n",
    "Q=\"has 'single' inside\"\nR='has \"double\" inside'\nS=`has 'both' \"kinds\"`\n",
    "DUP=one\nDUP=two\n",
    "URL=postgres://synthetic:synthetic@localhost:5432/db?ssl=true\n",
    "SPACES=  padded value  \nQUOTED=\"  kept  \"\n",
    "ESC=\"back\\\\slash\"\nESC2='back\\\\slash'\n",
];

const cases = inputs.map(input => ({
    input: input,
    parsed: Object.entries(dotenv.parse(input))
}));

const out = path.join(import.meta.dirname, "..", "crates", "vaultos-core", "tests", "fixtures", "dotenv-cases.json");

writeFileSync(out, JSON.stringify(cases, null, 2) + "\n");

console.log(`Wrote ${path.relative(process.cwd(), out)} (${cases.length} cases)`);
