import re
import time
import os
import requests
from lxml import etree
import random
import urllib.parse
import hashlib
import pickle

network_proxy_config = {
}


def persist_session_cookies(http_session_instance):
    with open('cookies.pkl', 'wb') as cookie_storage_file:
        pickle.dump(http_session_instance.cookies, cookie_storage_file)
    os.chmod('cookies.pkl', 0o600)


def retrieve_silver_coin_balance(http_request_headers, base_website_url, http_session_instance):
    user_credit_query_url = f"{base_website_url}/home.php?mod=spacecp&ac=credit&showcredit=1&inajax=1&ajaxtarget=extcreditmenu_menu"
    user_credit_response = http_session_instance.get(url=user_credit_query_url, headers=http_request_headers, proxies=network_proxy_config)
    if user_credit_response.status_code == 200:
        print("用户信息页面获取成功:")
    else:
        print("用户信息页面获取失败")
    html_source_content = user_credit_response.text
    silver_coin_extraction = re.findall('<span id="hcredit_2">(.*?)</span>', html_source_content)[0]
    if silver_coin_extraction:
        print('当前银币数量:', silver_coin_extraction)
        return [http_session_instance, http_request_headers]
    else:
        print("银币数量获取失败")
        return [http_session_instance, http_request_headers]


def url_encode_request_data(plain_text_data_dict):
    encoded_key_value_pairs = []
    for data_key, data_value in plain_text_data_dict.items():
        if data_key == 'noticeauthor':
            encoded_value_str = urllib.parse.quote(data_value.encode('gbk'), safe='~()*!.\'')
        else:
            encoded_value_str = urllib.parse.quote(data_value.encode('gbk'), safe='~()*!.\'+...')
        key_value_combination = f"{data_key}={encoded_value_str}"
        encoded_key_value_pairs.append(key_value_combination)
    return '&'.join(encoded_key_value_pairs)


def submit_forum_reply(page_parsed_content, reply_identifier, http_session_instance, http_request_headers, base_website_url, thread_identifier, forum_identifier):
    try:
        wrapped_content = f'"{page_parsed_content}"'
        html_parser_instance = etree.HTML(wrapped_content)
        form_security_hash = html_parser_instance.xpath("//input[@name='formhash']/@value")[0]
        author_notification = html_parser_instance.xpath("//input[@name='noticeauthor']/@value")[0]
        author_message_notice = html_parser_instance.xpath("//input[@name='noticeauthormsg']/@value")[0]
        signature_usage_flag = html_parser_instance.xpath("//input[@name='usesig']/@value")[0]
        parent_post_identifier = html_parser_instance.xpath("//input[@name='reppid']/@value")[0]
        notice_trim_string = html_parser_instance.xpath("//input[@name='noticetrimstr']/@value")[0]
        formatted_message_content = author_message_notice.replace('　', '\u3000').replace(' ', '+')
    except Exception as parsing_exception:
        print(f"❌ 解析参数失败：{parsing_exception}")
        return "", formatted_message_content if 'formatted_message_content' in locals() else ""

    reply_content_pool = ['啥也不说了，楼主就是给力', '谢谢楼主分享，祝搜书吧越办越好！', '看了LZ的帖子，我只想说一句很好很强大！', ]
    selected_reply_content = random.choice(reply_content_pool)
    unencoded_request_payload = {
        'formhash': form_security_hash,
        'handlekey': 'register',
        'noticeauthor': author_notification,
        'noticetrimstr': notice_trim_string,
        'noticeauthormsg': formatted_message_content,
        'usesig': signature_usage_flag,
        'reppid': parent_post_identifier,
        'reppost': reply_identifier,
        'subject': '',
        'message': selected_reply_content
    }
    request_query_parameters = {
        'mod': 'post',
        'infloat': 'yes',
        'action': 'reply',
        'fid': forum_identifier,
        'extra': '',
        'tid': thread_identifier,
        'replysubmit': 'yes',
        'inajax': '1',
    }

    while 1:
        try:
            encoded_request_payload = url_encode_request_data(unencoded_request_payload)
            break
        except Exception as encoding_exception:
            print('❌ 出现异常报错，重试：', unencoded_request_payload)
            print(encoding_exception)

    reply_submission_response = http_session_instance.post(f'{base_website_url}/forum.php', params=request_query_parameters, headers=http_request_headers, data=encoded_request_payload, proxies=network_proxy_config)
    reply_submission_response.encoding = 'gbk'
    raw_response_content = reply_submission_response.text
    persist_session_cookies(http_session_instance)

    import xml.etree.ElementTree as ET
    reply_success_status = False
    try:
        xml_root_element = ET.fromstring(raw_response_content)
        response_message_content = xml_root_element.text.strip() if xml_root_element.text else ""
        if any(keyword in response_message_content for keyword in ['恭喜', '成功', '发布成功', '回复成功']):
            reply_success_status = True
    except:
        if '成功' in raw_response_content:
            reply_success_status = True

    if reply_success_status:
        latest_credit_check_url = f"{base_website_url}/home.php?mod=spacecp&ac=credit&showcredit=1&inajax=1&ajaxtarget=extcreditmenu_menu"
        latest_credit_response = http_session_instance.get(url=latest_credit_check_url, headers=http_request_headers, proxies=network_proxy_config)
        latest_credit_response.encoding = 'gbk'
        current_silver_coin_count = re.findall('<span id="hcredit_2">(.*?)</span>', latest_credit_response.text)[0] if (
                    latest_credit_response.status_code == 200 and re.findall('<span id="hcredit_2">(.*?)</span>',
                                                                         latest_credit_response.text)) else "获取失败"

        print(f"\n✅ 评论成功！此次评论的帖子tid为 {thread_identifier}，评论的内容为「{selected_reply_content}」，当前银币数量为 {current_silver_coin_count}")
        print(f"等待60秒后再次评论...\n")
        time.sleep(60)
    else:
        print(f"\n❌ 评论失败（帖子tid：{thread_identifier}），响应前50字：{raw_response_content[:50]}")
        print(f"等待10秒后重试...\n")
        time.sleep(10)

    return raw_response_content, formatted_message_content


def fetch_forum_index_page(http_session_instance, http_request_headers, base_website_url):
    index_page_request_url = f'{base_website_url}/forum.php?mod=forumdisplay&fid=39&page=1'
    while 1:
        initial_page_response = http_session_instance.get(url=index_page_request_url, headers=http_request_headers, proxies=network_proxy_config)
        if initial_page_response.status_code == 200:
            return initial_page_response.text
        else:
            print('首页请求失败，再次请求')
            time.sleep(2)
            continue


def extract_thread_reply_parameters(http_session_instance, http_request_headers, base_website_url, index_page_html_content):
    page_source_content = index_page_html_content
    thread_identification_numbers = re.findall('id="normalthread_(.*?)"', page_source_content)
    if not thread_identification_numbers:
        print("未匹配到帖子ID，返回空")
        return "", "", http_session_instance, http_request_headers, base_website_url, "", ""
    while 1:
        try:
            random_index_selection = random.randint(0, len(thread_identification_numbers) - 1)
            break
        except Exception as random_selection_exception:
            print(f"随机选择帖子失败：{random_selection_exception}")
            random_index_selection = 0
            break
    thread_unique_identifier = str(thread_identification_numbers[random_index_selection])
    thread_view_parameters = {
        'mod': 'viewthread',
        'tid': thread_unique_identifier,
        'extra': 'page=1',
    }
    thread_view_response = http_session_instance.get(f'{base_website_url}/forum.php', params=thread_view_parameters, headers=http_request_headers, proxies=network_proxy_config)
    quick_reply_link_list = re.findall('<a class="fastre" href="(.*?)" onclick', thread_view_response.text)
    if not quick_reply_link_list:
        print("未匹配到回复链接，返回空")
        return "", "", http_session_instance, http_request_headers, base_website_url, thread_unique_identifier, ""
    quick_reply_identifier = quick_reply_link_list[0]
    try:
        forum_unique_identifier = quick_reply_identifier.split(';')[2].split('=')[1].split('&')[0]
        quick_reply_identifier = quick_reply_identifier.split(';')[4].split('=')[1].split('&')[0]
    except IndexError as parameter_extraction_exception:
        print(f"解析fid/reppost失败：{parameter_extraction_exception}")
        forum_unique_identifier = ""
    reply_form_parameters = {
        'mod': 'post',
        'action': 'reply',
        'fid': forum_unique_identifier,
        'tid': thread_unique_identifier,
        'reppost': quick_reply_identifier,
        'extra': 'page=1',
        'page': '1',
        'infloat': 'yes',
        'handlekey': 'reply',
        'inajax': '1',
        'ajaxtarget': 'fwin_content_reply',
    }
    http_request_headers['referer'] = f'{base_website_url}/forum.php?mod=viewthread&tid={int(thread_unique_identifier)}&extra=page%3D1'
    reply_form_response = http_session_instance.get(f'{base_website_url}/forum.php', params=reply_form_parameters, headers=http_request_headers, proxies=network_proxy_config)
    return reply_form_response.text, quick_reply_identifier, http_session_instance, http_request_headers, base_website_url, thread_unique_identifier, forum_unique_identifier


def record_md5_with_timestamp(csv_file_path, target_data_string, file_encoding='gbk'):
    try:
        md5_encryption_instance = hashlib.md5(target_data_string.encode(file_encoding)).hexdigest()
        current_time_stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        csv_formatted_line = f"{current_time_stamp},{md5_encryption_instance}\n"
        with open(csv_file_path, 'a', encoding=file_encoding) as csv_output_file:
            if csv_output_file.tell() == 0:
                csv_output_file.write("Timestamp,MD5\n")
            csv_output_file.write(csv_formatted_line)
    except Exception as csv_writing_exception:
        print(f"写入CSV失败：{csv_writing_exception}")


def perform_user_login(user_account_name, user_account_password, base_website_url):
    http_session_object = requests.session()
    valid_cookie_status = False
    http_request_header_config = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'zh-CN,zh;q=0.9',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': base_website_url,
        'referer': base_website_url,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36',
        'cache-control': 'no-cache',
        'pragma': 'no-cache',
        'priority': 'u=0, i',
        'sec-ch-ua': '"Google Chrome";v="129", "Not=A?Brand";v="8", "Chromium";v="129"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'iframe',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
    }

    try:
        if os.path.exists('cookies.pkl'):
            with open('cookies.pkl', 'rb') as cookie_file_handle:
                http_session_object.cookies.update(pickle.load(cookie_file_handle))
            print("已加载本地Cookie，验证有效性...")
            cookie_validation_url = f"{base_website_url}/home.php?mod=spacecp&ac=credit&showcredit=1&inajax=1&ajaxtarget=extcreditmenu_menu"
            cookie_test_response = http_session_object.get(cookie_validation_url, headers=http_request_header_config, proxies=network_proxy_config, timeout=10)
            if cookie_test_response.status_code == 200 and re.search('<span id="hcredit_2">.*?</span>', cookie_test_response.text):
                valid_cookie_status = True
                print("Cookie有效，无需重新登录")
        else:
            print("未找到本地Cookie文件，准备使用账号密码登录")
    except Exception as cookie_operation_exception:
        print(f'Cookie加载/验证失败：{cookie_operation_exception}，将使用账号密码登录')

    if not valid_cookie_status:
        print('开始使用用户名密码登录...')
        user_login_endpoint = f"{base_website_url}/member.php"
        login_request_parameters = {
            'mod': 'logging',
            'action': 'login',
            'loginsubmit': 'yes',
            'infloat': 'yes',
            'lssubmit': 'yes',
            'inajax': '1',
        }
        login_credentials = {
            'username': user_account_name,
            'password': user_account_password,
            'quickforward': "yes",
            'handlekey': "ls"
        }
        try:
            login_response = http_session_object.post(user_login_endpoint, headers=http_request_header_config, data=login_credentials, params=login_request_parameters, proxies=network_proxy_config, timeout=10)
            post_login_validation_url = f"{base_website_url}/home.php?mod=spacecp&ac=credit&showcredit=1&inajax=1&ajaxtarget=extcreditmenu_menu"
            post_login_test_response = http_session_object.get(post_login_validation_url, headers=http_request_header_config, proxies=network_proxy_config, timeout=10)
            if post_login_test_response.status_code == 200 and re.search('<span id="hcredit_2">.*?</span>', post_login_test_response.text):
                print(f'账号：{user_account_name} 登录成功！已自动保存Cookie')
                persist_session_cookies(http_session_object)
            else:
                print('登录失败：无法获取用户信息（可能账号密码错误或网络问题）')
                return None
        except Exception as login_request_exception:
            print(f'登录请求失败：{login_request_exception}')
            return None

    silver_coin_information = retrieve_silver_coin_balance(http_request_header_config, base_website_url, http_session_object)
    time.sleep(3)
    return silver_coin_information


def initiate_automated_reply_process():
    with open('config.txt', 'r+', encoding='UTF-8') as configuration_file_handle:
        configuration_file_handle.seek(0)
        configuration_file_lines = configuration_file_handle.readlines()
        while len(configuration_file_lines) < 4:
            configuration_file_lines.append('')
        user_login_name = configuration_file_lines[2].strip()
        user_login_password = configuration_file_lines[3].strip()
        target_website_base_url = configuration_file_lines[1].strip()

    if not target_website_base_url or user_login_name == 'username' or not user_login_name or not user_login_password:
        print('请确保config.txt中第一行填写有效URL，第二行填写用户名，第三行填写密码')
        return None, None

    login_attempt_count = 0
    while login_attempt_count < 3:
        try:
            login_success_data = perform_user_login(user_login_name, user_login_password, target_website_base_url)
            if login_success_data:
                return login_success_data, target_website_base_url
            else:
                login_attempt_count += 1
                print(f'登录失败，重试第{login_attempt_count}次')
                time.sleep(3)
        except Exception as login_attempt_exception:
            login_attempt_count += 1
            print(f'登录异常：{login_attempt_exception}，重试第{login_attempt_count}次')
            time.sleep(3)
    print("异常次数超过三次，退出登录")
    return None, None


if __name__ == '__main__':
    login_session_data, target_base_url = initiate_automated_reply_process()
    if not login_session_data or not target_base_url:
        print("初始化失败，退出程序")
        exit()
    current_reply_count = 0
    forum_index_html = fetch_forum_index_page(login_session_data[0], login_session_data[1], target_base_url)
    while current_reply_count < 3:
        try:
            thread_reply_data = extract_thread_reply_parameters(login_session_data[0], login_session_data[1], target_base_url, forum_index_html)
            reply_form_html, reply_identifier_str, current_session, current_headers, site_base_url, thread_id_str, forum_id_str = thread_reply_data
            if not reply_form_html or not thread_id_str or not forum_id_str:
                print(f'第{current_reply_count + 1}次获取帖子信息失败，跳过')
                time.sleep(10)
                continue
            reply_result, history_data = submit_forum_reply(reply_form_html, reply_identifier_str, current_session, current_headers, site_base_url, thread_id_str, forum_id_str)
            time.sleep(55)
            if '成功' in reply_result:
                record_md5_with_timestamp('./history_md5.csv', history_data)
                current_reply_count += 1
                print(f'第{current_reply_count}次评论成功')
            else:
                print(f'第{current_reply_count + 1}次评论失败，响应内容：{reply_result[:50]}')
        except Exception as reply_process_exception:
            print(f'第{current_reply_count + 1}次评论异常：{reply_process_exception}')
            time.sleep(10)
    retrieve_silver_coin_balance(current_headers, site_base_url, current_session)
