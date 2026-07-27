/**
 * Guara Cloud Logo Asset Generator
 *
 * Uses chroma-key (green screen) removal to cleanly extract the
 * illustration with perfect preservation of whites, clouds, and details.
 */
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(path.resolve(__dirname, 'package.json'));
const sharp = require('sharp');

const SRC = path.resolve(__dirname, '../logo-candidate-1.png');
const OUT = '/Users/victorbona/Code/Daedalus/positron-site/logos';

// Key color sampled from the corners of the source image
const KEY = { r: 124, g: 216, b: 63 };

/**
 * Chroma-key: remove green background using color distance.
 * Only the green screen gets removed. White fur, clouds, etc. are untouched.
 */
async function chromaKey(inputPath) {
  const { data, info } = await sharp(inputPath)
    .ensureAlpha()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const { width, height } = info;
  const innerDist = 50; // Below this → fully transparent
  const outerDist = 110; // Above this → fully opaque
  let removed = 0;

  for (let i = 0; i < data.length; i += 4) {
    const r = data[i],
      g = data[i + 1],
      b = data[i + 2];

    // Euclidean distance from key green
    const dr = r - KEY.r,
      dg = g - KEY.g,
      db = b - KEY.b;
    const dist = Math.sqrt(dr * dr + dg * dg + db * db);

    if (dist < innerDist) {
      // Definitely background
      data[i + 3] = 0;
      removed++;
    } else if (dist < outerDist) {
      // Edge transition - smooth alpha ramp
      const alpha = Math.round(((dist - innerDist) / (outerDist - innerDist)) * 255);
      data[i + 3] = alpha;

      // Green spill suppression: the illustration is purple-dominant,
      // so clamp green so it doesn't look unnaturally green at edges
      data[i + 1] = Math.min(g, Math.max(r, b) + 20);
    }
    // else: fully opaque, no changes
  }

  console.log(`   Chroma-key removed ${removed.toLocaleString()} background pixels`);

  return sharp(data, { raw: { width, height, channels: 4 } });
}

async function main() {
  console.log('POSITRON Logo Generator\n');

  // ── Step 1: Chroma-key background removal ──
  console.log('1. Chroma-key removing green background...');
  const transparent = await chromaKey(SRC);

  // Save the full transparent image (before any cropping)
  const fullTransBuf = await transparent.png().toBuffer();
  const trimmed = sharp(fullTransBuf).trim();
  const trimmedBuf = await trimmed.png().toBuffer();
  const trimmedMeta = await sharp(trimmedBuf).metadata();
  console.log(`   Trimmed to ${trimmedMeta.width}x${trimmedMeta.height}`);

  await sharp(trimmedBuf).toFile(path.join(OUT, 'logo-full-transparent.png'));
  console.log('   -> logo-full-transparent.png');

  // ── Step 2: Separate icon (wolf+clouds) from text ──
  console.log('\n2. Splitting icon and text...');

  // The illustration has the wolf+clouds on top and "<NAME>" text below.
  // Scan rows to find the gap between illustration and text.
  const rawTrimmed = await sharp(trimmedBuf).ensureAlpha().raw().toBuffer();
  const tw = trimmedMeta.width;

  // Find the gap: look for rows that are mostly transparent between the icon and text
  const rowOpacity = [];
  for (let y = 0; y < trimmedMeta.height; y++) {
    let opaquePixels = 0;
    for (let x = 0; x < tw; x++) {
      const idx = (y * tw + x) * 4;
      if (rawTrimmed[idx + 3] > 128) opaquePixels++;
    }
    rowOpacity.push(opaquePixels / tw);
  }

  // Find the gap between icon and text (a region of mostly transparent rows)
  let gapStart = -1,
    gapEnd = -1;
  const midY = Math.floor(trimmedMeta.height * 0.55); // Start looking from ~55% down
  for (let y = midY; y < trimmedMeta.height; y++) {
    if (rowOpacity[y] < 0.05) {
      // Mostly transparent row
      if (gapStart === -1) gapStart = y;
      gapEnd = y;
    } else if (gapStart !== -1 && y - gapEnd > 5) {
      break; // Found the gap, moved past it
    }
  }

  console.log(`   Icon/text gap found at rows ${gapStart}-${gapEnd}`);

  // Icon = everything above the gap
  const iconBuf = await sharp(trimmedBuf)
    .extract({ left: 0, top: 0, width: trimmedMeta.width, height: gapStart })
    .trim()
    .png()
    .toBuffer();
  const iconMeta = await sharp(iconBuf).metadata();

  await sharp(iconBuf).toFile(path.join(OUT, 'icon-transparent.png'));
  console.log(`   -> icon-transparent.png (${iconMeta.width}x${iconMeta.height})`);

  // Make square version of the icon (pad shorter dimension)
  const iconMax = Math.max(iconMeta.width, iconMeta.height);
  const squareIconBuf = await sharp(iconBuf)
    .resize(iconMax, iconMax, {
      fit: 'contain',
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    })
    .png()
    .toBuffer();

  await sharp(squareIconBuf).toFile(path.join(OUT, 'icon-square-transparent.png'));
  console.log(`   -> icon-square-transparent.png (${iconMax}x${iconMax})`);

  // ── Step 3: Favicons from transparent icon ──
  console.log('\n3. Generating favicons...');
  const sizes = [
    { s: 16, name: 'favicon-16.png' },
    { s: 32, name: 'favicon-32.png' },
    { s: 48, name: 'favicon-48.png' },
    { s: 96, name: 'favicon-96.png' },
    { s: 180, name: 'apple-touch-icon.png' },
    { s: 192, name: 'icon-192.png' },
    { s: 512, name: 'icon-512.png' },
  ];

  for (const { s, name } of sizes) {
    await sharp(squareIconBuf)
      .resize(s, s, { fit: 'contain', background: { r: 0, g: 0, b: 0, alpha: 0 } })
      .png()
      .toFile(path.join(OUT, name));
    console.log(`   -> ${name} (${s}x${s})`);
  }

  // ── Step 4: Branded favicon (icon on purple rounded square) ──
  console.log('\n4. Generating branded favicons (purple background)...');
  const base = 512;
  const padding = Math.floor(base * 0.1);
  const radius = Math.floor(base * 0.18);

  // Purple gradient rounded square background
  const brandBgSvg = Buffer.from(
    `<svg width="${base}" height="${base}">
      <defs>
        <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#7C6CFF"/>
          <stop offset="100%" stop-color="#5B4BDB"/>
        </linearGradient>
      </defs>
      <rect width="${base}" height="${base}" rx="${radius}" ry="${radius}" fill="url(#g)"/>
    </svg>`,
  );

  // Resize icon for the branded favicon
  const brandIcon = await sharp(squareIconBuf)
    .resize(base - padding * 2, base - padding * 2, {
      fit: 'contain',
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    })
    .png()
    .toBuffer();
  const brandIconMeta = await sharp(brandIcon).metadata();

  const brandedBase = await sharp(brandBgSvg)
    .composite([
      {
        input: brandIcon,
        left: Math.floor((base - brandIconMeta.width) / 2),
        top: Math.floor((base - brandIconMeta.height) / 2),
      },
    ])
    .png()
    .toBuffer();

  await sharp(brandedBase).toFile(path.join(OUT, 'favicon-branded-512.png'));
  console.log('   -> favicon-branded-512.png');

  for (const s of [16, 32, 48, 96, 180, 192]) {
    const name = `favicon-branded-${s}.png`;
    await sharp(brandedBase).resize(s, s).png().toFile(path.join(OUT, name));
    console.log(`   -> ${name}`);
  }

  // ── Step 5: OG Image ──
  console.log('\n5. Creating OG image...');
  const ogW = 1200,
    ogH = 630;

  const ogBg = Buffer.from(
    `<svg width="${ogW}" height="${ogH}">
      <defs>
        <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#140C2E"/>
          <stop offset="50%" stop-color="#1A1040"/>
          <stop offset="100%" stop-color="#251650"/>
        </linearGradient>
        <radialGradient id="glow" cx="50%" cy="40%" r="45%">
          <stop offset="0%" stop-color="#7C6CFF" stop-opacity="0.12"/>
          <stop offset="100%" stop-color="#7C6CFF" stop-opacity="0"/>
        </radialGradient>
      </defs>
      <rect width="${ogW}" height="${ogH}" fill="url(#bg)"/>
      <ellipse cx="${ogW / 2}" cy="${ogH * 0.38}" rx="400" ry="250" fill="url(#glow)"/>
    </svg>`,
  );
  const ogBgBuf = await sharp(ogBg).png().toBuffer();

  // Use the icon (not full logo) — we'll render the text separately for better quality
  const ogIconH = Math.floor(ogH * 0.55);
  const ogIcon = await sharp(iconBuf).resize(null, ogIconH, { fit: 'inside' }).png().toBuffer();
  const ogIconMeta = await sharp(ogIcon).metadata();

  const ogText = Buffer.from(
    `<svg width="${ogW}" height="70">
      <text x="${ogW / 2}" y="50" text-anchor="middle"
        font-family="system-ui, -apple-system, sans-serif"
        font-size="46" font-weight="700"
        letter-spacing="8" fill="white" opacity="0.95">POSITRON</text>
    </svg>`,
  );

  const ogTagline = Buffer.from(
    `<svg width="${ogW}" height="32">
      <text x="${ogW / 2}" y="22" text-anchor="middle"
        font-family="system-ui, -apple-system, sans-serif"
        font-size="17" font-weight="400"
        fill="white" opacity="0.45">The observability database for native logs and traces</text>
    </svg>`,
  );

  const ogIconTop = 45;
  const ogTextTop = ogIconTop + ogIconMeta.height + 20;

  await sharp(ogBgBuf)
    .composite([
      { input: ogIcon, left: Math.floor((ogW - ogIconMeta.width) / 2), top: ogIconTop },
      { input: ogText, left: 0, top: ogTextTop },
      { input: ogTagline, left: 0, top: ogTextTop + 58 },
    ])
    .png()
    .toFile(path.join(OUT, 'og-image.png'));
  console.log('   -> og-image.png (1200x630)');

  // ── Step 6: White-bg square (for contexts that need a solid background) ──
  console.log('\n6. Creating utility variants...');

  const sqSize = 1024;
  const fullForSquare = await sharp(trimmedBuf)
    .resize(Math.floor(sqSize * 0.85), Math.floor(sqSize * 0.85), { fit: 'inside' })
    .png()
    .toBuffer();
  const fsMeta = await sharp(fullForSquare).metadata();

  await sharp({
    create: {
      width: sqSize,
      height: sqSize,
      channels: 4,
      background: { r: 255, g: 255, b: 255, alpha: 255 },
    },
  })
    .composite([
      {
        input: fullForSquare,
        left: Math.floor((sqSize - fsMeta.width) / 2),
        top: Math.floor((sqSize - fsMeta.height) / 2),
      },
    ])
    .png()
    .toFile(path.join(OUT, 'logo-on-white.png'));
  console.log('   -> logo-on-white.png (1024x1024)');

  // Dark bg variant
  await sharp({
    create: {
      width: sqSize,
      height: sqSize,
      channels: 4,
      background: { r: 20, g: 16, b: 46, alpha: 255 },
    },
  })
    .composite([
      {
        input: fullForSquare,
        left: Math.floor((sqSize - fsMeta.width) / 2),
        top: Math.floor((sqSize - fsMeta.height) / 2),
      },
    ])
    .png()
    .toFile(path.join(OUT, 'logo-on-dark.png'));
  console.log('   -> logo-on-dark.png (1024x1024)');

  console.log('\n--- Done ---\n');
}

main().catch(console.error);
