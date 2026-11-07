// Draws the menu bar icon (the app icon's dial, simplified for 16 pt) and writes PNGs to
// build/tray. macOS uses the black "Template" images and tints them itself; Linux panels get
// a light variant. Run after changing the drawing: node scripts/make-tray-icons.mjs
import { mkdirSync, writeFileSync } from "node:fs";

import { deflateSync } from "node:zlib";

// A combination dial: outer ring, eight index marks (the long one on top), and a knob.
const MARKS = Array.from({ length: 8 }, (_, i) => ({ a: (i * 45 - 90) * Math.PI / 180, from: i === 0 ? 3.3 : 4.4 }));

// Coverage of one point, in the 16-unit design grid. Positive shapes are unioned, then the
// attention dot's clearance ring is subtracted and the dot added.
function inside(x, y, attention) {
    const dx = x - 8, dy = y - 8, r = Math.hypot(dx, dy);
    let on = Math.abs(r - 6.6) <= 0.75 || r <= 2.1;
    for (const {a, from} of MARKS) {
        const along = dx * Math.cos(a) + dy * Math.sin(a), across = Math.abs(-dx * Math.sin(a) + dy * Math.cos(a));
        if (along >= from && along <= 5.9 && across <= 0.55) on = true;
    }
    if (attention) {
        const d = Math.hypot(x - 13.2, y - 2.8);
        if (d <= 3.4) on = d <= 2.3;
    }
    return on;
}

function render(scale, attention, rgb) {
    const size = 16 * scale, ss = 4, px = Buffer.alloc(size * size * 4);
    for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) {
        let hits = 0;
        for (let sy = 0; sy < ss; sy++) for (let sx = 0; sx < ss; sx++) if (inside((x + (sx + 0.5) / ss) / scale, (y + (sy + 0.5) / ss) / scale, attention)) hits++;
        const i = (y * size + x) * 4;
        [ px[i], px[i + 1], px[i + 2] ] = rgb;
        px[i + 3] = Math.round(255 * hits / (ss * ss));
    }
    return png(size, px);
}

const CRC = Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
});

function chunk(type, data) {
    const body = Buffer.concat([ Buffer.from(type, "ascii"), data ]);
    let c = 0xffffffff;
    for (const b of body) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
    const out = Buffer.alloc(body.length + 8);
    out.writeUInt32BE(data.length, 0);
    body.copy(out, 4);
    out.writeUInt32BE((c ^ 0xffffffff) >>> 0, body.length + 4);
    return out;
}

function png(size, rgba) {
    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(size, 0);
    ihdr.writeUInt32BE(size, 4);
    ihdr[8] = 8;
    ihdr[9] = 6;
    const rows = Buffer.alloc(size * (size * 4 + 1));
    for (let y = 0; y < size; y++) rgba.copy(rows, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
    return Buffer.concat([ Buffer.from([ 137, 80, 78, 71, 13, 10, 26, 10 ]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(rows, { level: 9 })), chunk("IEND", Buffer.alloc(0)) ]);
}

mkdirSync("build/tray", { recursive: true });

for (const [name, attention] of [ [ "tray", false ], [ "trayAttention", true ] ]) {
    writeFileSync(`build/tray/${name}Template.png`, render(1, attention, [ 0, 0, 0 ]));
    writeFileSync(`build/tray/${name}Template@2x.png`, render(2, attention, [ 0, 0, 0 ]));
    writeFileSync(`build/tray/${name}Light.png`, render(2, attention, [ 236, 236, 240 ]));
}

console.log("Wrote menu bar icons to build/tray.");
