/**
 * Generate extension icons from Certen logo
 *
 * This script regenerates icons from the source logo if available.
 * Pre-built icons are committed in public/icons/ and copied to dist by webpack,
 * so this step is only needed when updating the logo.
 */
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const srcLogo = path.resolve(__dirname, '../../certen-colors-assets-icons-themes/logos/logo_only.png');
const outDir = path.resolve(__dirname, '../dist/public/icons');

if (!fs.existsSync(srcLogo)) {
  console.log('Source logo not found, skipping icon generation.');
  console.log('Using pre-built icons from public/icons/ (copied to dist by webpack).');
  process.exit(0);
}

fs.mkdirSync(outDir, { recursive: true });

const sizes = [16, 32, 48, 128];

Promise.all(sizes.map(size =>
  sharp(srcLogo)
    .resize(size, size)
    .png()
    .toFile(path.join(outDir, `icon-${size}.png`))
    .then(() => console.log(`Created icon-${size}.png`))
)).then(() => console.log('All icons created!'))
  .catch(err => console.error('Error creating icons:', err));
