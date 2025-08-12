/* hexo-qzone-script */
/* scripts/qzone.js */

const puppeteer = require('puppeteer');
const fs = 'fs';
const path = 'path';

// [重要] 请在这里配置您的信息
const CONFIG = {
    // 第二步中获取到的 Chrome "个人资料路径"
    CHROME_USER_DATA_PATH: 'C:\\Users\\saevios\\AppData\\Local\\Google\\Chrome\\User Data',
    // 您的 QQ 号
    QQ_NUMBER: '1127499339',
    // 您希望生成的 HTML 文件标题
    HTML_TITLE: '我的心情随笔',
    // 加载页面的超时时间 (毫秒)
    TIMEOUT: 30000,
};

// QQ空间最新说说的选择器 (如果未来失效，需要更新这里)
// 经过分析，通常第一条说说的内容在这个CSS路径下
const LATEST_NOTE_SELECTOR = '.feed_content.feed_summary';

// 写入文件的目标路径 (Hexo source 目录)
const OUTPUT_FILE_PATH = path.join(hexo.source_dir, 'notes', 'index.html');

// 核心抓取函数
async function fetchLatestQzoneNote() {
    hexo.log.info('>>>>> 开始抓取最新QQ空间说说...');

    let browser;
    try {
        hexo.log.info('>>>>> 正在启动浏览器...');
        browser = await puppeteer.launch({
            headless: true, // 使用无头模式，不在前台显示浏览器界面
            userDataDir: CONFIG.CHROME_USER_DATA_PATH, // 加载用户数据
            args: ['--no-sandbox', '--disable-setuid-sandbox'],
            timeout: CONFIG.TIMEOUT,
            // 如果遇到问题，可以尝试改为 headless: false 在前台运行以观察
        });

        const page = await browser.newPage();
        const qzoneUrl = `https://user.qzone.qq.com/${CONFIG.QQ_NUMBER}/main`;

        hexo.log.info(`>>>>> 正在访问页面: ${qzoneUrl}`);
        await page.goto(qzoneUrl, {
            waitUntil: 'networkidle2', // 等待网络空闲
            timeout: CONFIG.TIMEOUT,
        });

        hexo.log.info('>>>>> 等待说说内容加载...');
        await page.waitForSelector(LATEST_NOTE_SELECTOR, { timeout: CONFIG.TIMEOUT });

        const latestNote = await page.evaluate((selector) => {
            const element = document.querySelector(selector);
            return element ? element.innerText : null;
        }, LATEST_NOTE_SELECTOR);

        if (latestNote) {
            hexo.log.info(`>>>>> 成功抓取到说说: ${latestNote.substring(0, 30)}...`);
            return latestNote.trim();
        } else {
            hexo.log.warn('>>>>> 未能抓取到说说内容，元素可能未找到。');
            return null;
        }

    } catch (error) {
        hexo.log.error('>>>>> 抓取过程中发生错误:', error.message);
        return null;
    } finally {
        if (browser) {
            await browser.close();
            hexo.log.info('>>>>> 浏览器已关闭。');
        }
    }
}

// 生成 HTML 内容的函数
function createHtmlContent(note) {
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${CONFIG.HTML_TITLE}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; line-height: 1.6; padding: 20px; max-width: 800px; margin: 40px auto; background-color: #f9f9f9; color: #333; }
    .note-container { background-color: #fff; border: 1px solid #ddd; border-radius: 8px; padding: 25px; box-shadow: 0 2px 5px rgba(0,0,0,0.05); }
    h1 { color: #555; }
    p { white-space: pre-wrap; font-size: 1.1em; }
    footer { font-size: 0.8em; color: #999; text-align: right; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="note-container">
    <h1>${CONFIG.HTML_TITLE}</h1>
    <p>${note.replace(/\n/g, '<br>')}</p> <!-- 将换行符转换成 <br> -->
    <footer>更新于: ${new Date().toLocaleString()}</footer>
  </div>
</body>
</html>
  `;
}

// 注册 Hexo `generateBefore` 事件钩子
hexo.on('generateBefore', async function() {
    const noteContent = await fetchLatestQzoneNote();

    if (noteContent) {
        const htmlContent = createHtmlContent(noteContent);
        // 确保 notes 文件夹存在
        const dir = path.dirname(OUTPUT_FILE_PATH);
        if (!fs.existsSync(dir)){
            fs.mkdirSync(dir, { recursive: true });
        }
        // 写入文件
        fs.writeFileSync(OUTPUT_FILE_PATH, htmlContent);
        hexo.log.info(`>>>>> 说说已成功写入到: ${OUTPUT_FILE_PATH}`);
    } else {
        hexo.log.warn('>>>>> 获取说说失败，本次不更新文件。');
    }
});