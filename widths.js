const { chromium } = require('playwright');
const pages = ['index.html','endpoints.html','endpoint-detail.html','ai-center.html','rag-center.html','assistant.html','incident.html'];
(async () => {
  const b = await chromium.launch();
  for (const w of [1280, 1024]) {
    const ctx = await b.newContext({ viewport: { width: w, height: 900 } });
    for (const p of pages) {
      const pg = await ctx.newPage(); const errs = [];
      pg.on('pageerror', e => errs.push(e.message));
      pg.on('console', m => { if (m.type()==='error') errs.push(m.text()); });
      await pg.goto('http://localhost:8807/' + p, { waitUntil: 'networkidle' });
      await pg.waitForTimeout(1200);
      const r = await pg.evaluate(() => {
        const over = document.documentElement.scrollWidth > window.innerWidth + 2;
        let bad = [];
        document.querySelectorAll('*').forEach(el => {
          if (el.scrollWidth > el.clientWidth + 4 && getComputedStyle(el).overflowX === 'visible' && el.clientWidth > 0)
            bad.push(el.className && typeof el.className === 'string' ? el.className.slice(0,40) : el.tagName);
        });
        return { over, bad: [...new Set(bad)].slice(0,6) };
      });
      if (w === 1024 && p === 'index.html') await pg.screenshot({path:'/home/user/workspace/securewatch-ai/shots/index-1024.png', fullPage:true});
      console.log(w, p, r.over ? 'PAGE-OVERFLOW' : 'ok', JSON.stringify(r.bad), errs.length?JSON.stringify(errs.slice(0,3)):'');
      await pg.close();
    }
    await ctx.close();
  }
  await b.close();
})();
