const { chromium } = require('playwright');
(async () => {
  const pages = process.argv.slice(2);
  const b = await chromium.launch();
  const ctx = await b.newContext({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
  for (const p of pages) {
    const pg = await ctx.newPage();
    const errs = [];
    pg.on('console', m => { if (m.type() === 'error') errs.push(m.text()); });
    pg.on('pageerror', e => errs.push('PAGEERROR: ' + e.message));
    await pg.goto('http://localhost:8807/' + p, { waitUntil: 'networkidle' });
    await pg.waitForTimeout(1800);
    await pg.screenshot({ path: '/home/user/workspace/securewatch-ai/shots/' + p.replace('.html','') + '.png', fullPage: true });
    const ow = await pg.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 2 ? 'H-OVERFLOW' : 'ok');
    console.log(p, ow, errs.length ? JSON.stringify(errs.slice(0,5)) : 'no-console-errors');
    await pg.close();
  }
  await b.close();
})();
