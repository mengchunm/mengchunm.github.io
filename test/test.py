import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# --- 用户配置 ---
# 您的 Chrome 用户数据路径
user_data_dir = r"C:/Users/saevio/AppData/Local/Google/Chrome/User Data"
# 您的 Chrome.exe 文件路径
chrome_executable_path = r"D:\environment\chrome-win64\chrome.exe"
# 您要访问的 QQ 空间 URL
qzone_url = "https://user.qzone.qq.com/1127499339/main"
# 用于存放最新说说的 HTML 文件名
output_html_file = "index.html"
# 说说内容在 HTML 中的 class name (这可能需要您手动确认)
# 您可以右键点击说说内容，选择“检查”，然后在开发者工具中找到包含说说文本的元素的 class
# 这是一个可能的 class name，如果无法正常获取，请根据实际情况修改
post_class_name = "content"


def get_latest_qzone_post():
    """
    启动 Chrome 浏览器，访问指定的 QQ 空间，获取最新一条说说并保存到 HTML 文件。
    """
    chrome_options = Options()
    chrome_options.add_argument(f"user-data-dir={user_data_dir}")
    chrome_options.binary_location = chrome_executable_path

    # 在某些情况下，您可能还需要指定 profile 目录
    # chrome_options.add_argument("--profile-directory=Default") # 或者其他 Profile 名称

    driver = webdriver.Chrome(options=chrome_options)

    try:
        driver.get(qzone_url)

        # 等待页面加载，特别是说说的 iframe 加载出来
        # 您需要根据您的网络情况调整等待时间
        WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.ID, "app_canvas_frame"))
        )

        # QQ 空间的说说在 iframe 中，需要先切换到 iframe
        driver.switch_to.frame("app_canvas_frame")

        # 等待说说内容元素出现 [1, 3, 6]
        latest_post_element = WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.CLASS_NAME, post_class_name))
        )

        # 获取说说的文本内容 [14, 19, 20]
        latest_post_text = latest_post_element.text

        # 将获取到的内容写入 HTML 文件 [2, 4, 5]
        with open(output_html_file, 'w', encoding='utf-8') as f:
            html_content = f"""
            <!DOCTYPE html>
            <html lang="zh-CN">
            <head>
                <meta charset="UTF-8">
                <title>我的最新说说</title>
            </head>
            <body>
                <h1>我的最新说说</h1>
                <p>{latest_post_text}</p>
            </body>
            </html>
            """
            f.write(html_content)

        print(f"成功获取最新说说并写入到 {output_html_file}")
        print(f"内容：{latest_post_text}")

    except Exception as e:
        print(f"在获取说说时发生错误: {e}")
    finally:
        # 关闭浏览器
        driver.quit()

if __name__ == "__main__":
    get_latest_qzone_post()