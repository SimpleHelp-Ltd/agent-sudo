// Copyright 2026 SimpleHelp
// SPDX-License-Identifier: Apache-2.0

const {chromium}=require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const fs=require('fs');
(async()=>{
const browser=await chromium.launch({headless:true});
const context=await browser.newContext({permissions:['clipboard-read','clipboard-write']});
const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
const url=process.argv[2]||'file://'+process.cwd()+'/website/agent-sudo.html';
const response=await page.goto(url);await page.evaluate(()=>document.fonts.ready);
if(url.startsWith('https:')){
 if(!response.ok() || !response.headers()['content-type']?.startsWith('text/html') || response.headers()['content-disposition']?.includes('attachment'))throw Error('HTML not served as a page');
 await page.locator('#copy').click();if(await page.evaluate(()=>navigator.clipboard.readText())!==fs.readFileSync('website/install-command.txt','utf8').trim())throw Error('real clipboard');
}
const command=fs.readFileSync('website/install-command.txt','utf8').trim();
if(await page.locator('#install-command').textContent()!==command)throw Error('command mismatch');
for(const width of [375,768,1280]){
 await page.setViewportSize({width,height:900});
 if(!await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth))throw Error('horizontal overflow '+width);
 await page.screenshot({path:'target/page-'+width+'.png',fullPage:true});
}
await page.evaluate(()=>{window.copied=null;Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async t=>{window.copied=t}}})});
await page.locator('#copy').click();if(await page.evaluate(()=>window.copied)!==command)throw Error('copy value');
if(await page.locator('#copy-status').textContent()!=='Command copied.')throw Error('copy status');
await page.evaluate(()=>Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:async()=>{throw Error('denied')}}}));await page.locator('#copy').click();
if(!(await page.locator('#copy-status').textContent()).includes('Copy was blocked'))throw Error('fallback');
if(await page.evaluate(()=>getSelection().toString())!==command)throw Error('fallback selection');
if(errors.length)throw Error(errors.join(','));
await page.locator('#copy').focus();
await page.keyboard.press('Tab');await page.keyboard.press('Shift+Tab');
if(!await page.locator('#copy').evaluate(e=>e===document.activeElement && getComputedStyle(e).outlineStyle==='solid'))throw Error('keyboard focus missing');
await page.keyboard.press('Enter');
if(!(await page.locator('#copy-status').textContent()).includes('Copy was blocked'))throw Error('keyboard activation');
if(await page.locator('#administrators').count()!==1||await page.locator('#agents').count()!==1)throw Error('audiences');
if(!await page.evaluate(()=>document.fonts.check('400 16px "Noto Sans"')&&document.fonts.check('700 40px Ubuntu')))throw Error('brand fonts did not load');
const brand=await page.evaluate(()=>({body:getComputedStyle(document.body).fontFamily,heading:getComputedStyle(document.querySelector('h1')).fontFamily,accent:getComputedStyle(document.querySelector('h1')).color,button:getComputedStyle(document.querySelector('button')).backgroundColor}));
if(!brand.body.includes('Noto Sans')||!brand.heading.includes('Ubuntu')||brand.accent!=='rgb(126, 102, 204)'||brand.button!=='rgb(117, 71, 255)')throw Error('SimpleHelp brand styles');
if(!(await page.locator('#administrators').innerText()).includes('agent-sudo revoke all'))throw Error('administrator creator revocation missing');
if(!(await page.locator('#agents').innerText()).includes('issued to your account'))throw Error('recipient scope clarification missing');
const links=await page.locator('a').evaluateAll(as=>as.map(a=>a.href));
fs.writeFileSync('target/browser-check.json',JSON.stringify({url,widths:[375,768,1280],copySuccess:true,copyDeniedFallback:true,keyboardFocus:true,keyboardActivation:true,brand,errors,links},null,2));
await browser.close();console.log('PASS responsive layout, copy success/denial fallback, command equality, browser errors');
})().catch(e=>{console.error(e);process.exit(1)});
