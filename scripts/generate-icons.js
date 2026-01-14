/**
 * Generate extension icons from Certen logo
 */
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');

const srcLogo = path.resolve(__dirname, '../../certen-colors-assets-icons-themes/logos/logo_only.png');
const outDir = path.resolve(__dirname, '../dist/public/icons');

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
