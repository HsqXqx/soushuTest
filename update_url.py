# -*- coding: utf-8 -*-
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def eliminate_terminating_slash(unprocessed_uniform_resource_locator: str) -> str:
    if unprocessed_uniform_resource_locator and unprocessed_uniform_resource_locator.endswith('/'):
        return unprocessed_uniform_resource_locator[:-1]
    return unprocessed_uniform_resource_locator


def retrieve_contemporary_soushuba_address() -> str:
    preset_permanent_address = "http://www.soushu2035.com"
    operational_permanent_address = preset_permanent_address
    configuration_modified_flag = False

    try:
        with open('config.txt', 'r+', encoding='utf-8') as configuration_file_handle:
            configuration_file_lines = configuration_file_handle.readlines()
            if configuration_file_lines:
                raw_initial_line_content = configuration_file_lines[0].strip()
                if raw_initial_line_content:
                    operational_permanent_address = raw_initial_line_content
                else:
                    print(f"检测到config.txt第一行为空，写入默认地址：{preset_permanent_address}")
                    configuration_file_lines[0] = f"{preset_permanent_address}\n"
                    configuration_modified_flag = True
            else:
                print(f"config.txt为空，写入默认地址：{preset_permanent_address}")
                configuration_file_lines.append(f"{preset_permanent_address}\n")
                configuration_modified_flag = True

            while len(configuration_file_lines) < 2:
                configuration_file_lines.append('')

            if configuration_modified_flag:
                configuration_file_handle.seek(0)
                configuration_file_handle.writelines(configuration_file_lines)
                configuration_file_handle.truncate()

    except FileNotFoundError:
        print(f"未找到config.txt，创建文件并写入默认地址：{preset_permanent_address}")
        with open('config.txt', 'w', encoding='utf-8') as configuration_file_handle:
            configuration_file_handle.write(f"{preset_permanent_address}\n")
            configuration_file_handle.write("\n")
    except Exception as exception_instance:
        print(f"处理config.txt时出错：{exception_instance}，将使用默认地址")
        operational_permanent_address = preset_permanent_address

    operational_permanent_address = eliminate_terminating_slash(operational_permanent_address)
    if not operational_permanent_address.startswith(('http://', 'https://')):
        print(f"地址缺少协议头，自动补全为：http://{operational_permanent_address}")
        operational_permanent_address = f"http://{operational_permanent_address}"

    http_request_headers = {
        "User-Agent": "PostmanRuntime-ApipostRuntime/1.1.0",
        "Accept": "*/*",
        "Connection": "keep-alive"
    }

    http_session_instance = requests.Session()
    http_session_instance.headers.update(http_request_headers)
    maximum_redirect_depth = 5

    try:
        initial_http_response = http_session_instance.get(
            operational_permanent_address,
            allow_redirects=False,
            timeout=20,
            verify=False
        )
        print(f"第一次访问：{initial_http_response.url} | 状态码：{initial_http_response.status_code}")

        def analyze_redirect_chain(current_response, current_depth=0):
            if current_depth >= maximum_redirect_depth:
                print(f"跳转深度达到上限（{maximum_redirect_depth}次），停止穿透")
                return current_response.url

            html_parser_instance = BeautifulSoup(current_response.text, 'html.parser')

            meta_redirect_tag = html_parser_instance.find('meta', {'http-equiv': re.compile('refresh', re.I)})
            if meta_redirect_tag:
                meta_content_attribute = meta_redirect_tag.get('content', '')
                if 'url=' in meta_content_attribute:
                    extracted_redirect_url = meta_content_attribute.split('url=')[-1].strip()
                    if extracted_redirect_url.startswith('/'):
                        parsed_response_url = urlparse(current_response.url)
                        extracted_redirect_url = f"{parsed_response_url.scheme}://{parsed_response_url.netloc}{extracted_redirect_url}"
                    extracted_redirect_url = eliminate_terminating_slash(extracted_redirect_url)
                    print(f"检测到meta跳转（{current_depth+1}次）：{extracted_redirect_url}")
                    new_redirect_response = http_session_instance.get(extracted_redirect_url, allow_redirects=False, timeout=20, verify=False)
                    return analyze_redirect_chain(new_redirect_response, current_depth+1)

            urls_array_match = re.search(r'urls\[\d+\]="(.*?)"', current_response.text)
            if urls_array_match:
                urls_extracted_url = urls_array_match.group(1)
                parsed_response_url = urlparse(current_response.url)
                urls_extracted_url = f"{parsed_response_url.scheme}://{parsed_response_url.netloc}{urls_extracted_url}"
                urls_extracted_url = eliminate_terminating_slash(urls_extracted_url)
                print(f"检测到urls跳转（{current_depth+1}次）：{urls_extracted_url}")
                new_redirect_response = http_session_instance.get(urls_extracted_url, allow_redirects=False, timeout=20, verify=False)
                return analyze_redirect_chain(new_redirect_response, current_depth+1)

            target_keywords = ['搜书吧', '官方地址', '点击访问', '立即前往', '最新地址']
            valid_hyperlinks = []
            for anchor_element in html_parser_instance.find_all('a', href=True):
                anchor_text_content = anchor_element.text.strip()
                anchor_href_value = anchor_element['href'].strip()
                if (any(keyword in anchor_text_content or keyword in anchor_href_value for keyword in target_keywords)
                    and anchor_href_value.startswith(('http://', 'https://'))):
                    anchor_href_value = eliminate_terminating_slash(anchor_href_value)
                    valid_hyperlinks.append(anchor_href_value)

            if valid_hyperlinks:
                return valid_hyperlinks[0]

            all_extracted_links = re.findall(r'https?://[^\s"]+', current_response.text)
            approved_domain_keywords = ['soushu', 'ss8', 'book', 'pmvd', 'allshu', 'soushufabu']
            relevant_soushu_links = []
            for link_candidate in all_extracted_links:
                cleaned_link_candidate = eliminate_terminating_slash(link_candidate)
                if any(domain_keyword in cleaned_link_candidate for domain_keyword in approved_domain_keywords):
                    relevant_soushu_links.append(cleaned_link_candidate)
            if relevant_soushu_links:
                return relevant_soushu_links[0]

            return eliminate_terminating_slash(current_response.url)

        resolved_target_address = analyze_redirect_chain(initial_http_response)
        resolved_target_address = eliminate_terminating_slash(resolved_target_address)

        validation_http_response = http_session_instance.get(resolved_target_address, timeout=20, verify=False)
        if validation_http_response.status_code == 200:
            try:
                with open('config.txt', 'r+', encoding='utf-8') as configuration_file_handle:
                    configuration_file_lines = configuration_file_handle.readlines()
                    while len(configuration_file_lines) < 2:
                        configuration_file_lines.append('')
                    configuration_file_lines[1] = f"{resolved_target_address}\n"
                    configuration_file_handle.seek(0)
                    configuration_file_handle.writelines(configuration_file_lines)
                    configuration_file_handle.truncate()
                print(f"有效地址已写入config.txt第二行：{resolved_target_address}")
            except Exception as exception_instance:
                print(f"写入有效地址失败：{exception_instance}")
            return resolved_target_address
        else:
            print(f"地址验证失败（状态码：{validation_http_response.status_code}）：{resolved_target_address}")
            return None

    except Exception as exception_instance:
        print(f"获取失败：{str(exception_instance)[:150]}")
        return None


if __name__ == '__main__':
    print("开始获取搜书吧当前有效地址...")
    active_soushuba_address = retrieve_contemporary_soushuba_address()
    if active_soushuba_address:
        print(f"\n✅ 成功获取！")
        print(f"当前有效地址：{active_soushuba_address}")
        extracted_hostname = urlparse(active_soushuba_address).hostname
        print(f"Hostname：{extracted_hostname}")
    else:
        print(f"\n❌ 获取失败，请检查网络或稍后重试")
