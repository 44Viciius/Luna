import requests
import argparse
import re
import json
import threading
import time
from urllib.parse import urlparse

def print_logo():
    logo = r"""
__/\\\_____________________________________________________________________________________/\\\\\\\\\\__        
 _\/\\\____________________________________________________________________________/\\\___/\\\///////\\\_       
  _\/\\\_________________________________________________________________________/\\\//___\///______/\\\__      
   _\/\\\______________/\\\____/\\\__/\\/\\\\\\____/\\\\\\\\\__________________/\\\//_____________/\\\//___     
    _\/\\\_____________\/\\\___\/\\\_\/\\\////\\\__\////////\\\______________/\\\//_______________\////\\\__    
     _\/\\\_____________\/\\\___\/\\\_\/\\\__\//\\\___/\\\\\\\\\\____________\////\\\_________________\//\\\_   
      _\/\\\_____________\/\\\___\/\\\_\/\\\___\/\\\__/\\\/////\\\_______________\////\\\_____/\\\______/\\\__  
       _\/\\\\\\\\\\\\\\\_\//\\\\\\\\\__\/\\\___\/\\\_\//\\\\\\\\/\\_________________\////\\\_\///\\\\\\\\\/___ 
        _\///////////////___\/////////___\///____\///___\////////\//_____________________\///____\/////////_____  
                  By 44Viciius<3
    """
    print(logo)

def test_idor(url, param_name, valid_value, invalid_value):
    valid_url = url.replace(param_name, valid_value)
    invalid_url = url.replace(param_name, invalid_value)

    response_valid = requests.get(valid_url)
    response_invalid = requests.get(invalid_url)

    if response_valid.status_code == 200 and response_invalid.status_code != 200:
        print(f"Posible vulnerabilidad IDOR detectada: {param_name} en {url}")
        return True
    return False

def test_weak_authentication(url, token):
    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 401:
        print(f"Autenticación débil detectada en {url}")
        return True
    return False

def test_sql_injection(url, payloads):
    for payload in payloads:
        response = requests.get(url + payload)
        if "error" in response.text.lower() or response.status_code == 500:
            print(f"Posible inyección SQL detectada en {url} con el payload: {payload}")
            return True
    return False

def test_xss(url, payloads):
    for payload in payloads:
        response = requests.get(url + payload)
        if payload in response.text:
            print(f"Posible vulnerabilidad XSS detectada en {url} con el payload: {payload}")
            return True
    return False

def test_https_security(url):
    parsed_url = urlparse(url)
    response = requests.get(url, verify=True, timeout=5)

    if response.status_code != 200:
        print(f"HTTPS no seguro en {url}")
        return False

    if 'Strict-Transport-Security' not in response.headers:
        print(f"Falta HSTS en {url}")
        return False

    print(f"HTTPS es seguro en {url}")
    return True

def scan_api(url, param_name, valid_value, invalid_value, weak_token, sql_payloads, xss_payloads):
    print(f"Iniciando escaneo de vulnerabilidades en {url}...")

    test_idor(url, param_name, valid_value, invalid_value)
    test_weak_authentication(url, weak_token)
    test_sql_injection(url, sql_payloads)
    test_xss(url, xss_payloads)
    test_https_security(url)

def scan_api_in_parallel(apis, param_name, valid_value, invalid_value, weak_token, sql_payloads, xss_payloads):
    threads = []
    for api in apis:
        t = threading.Thread(target=scan_api, args=(api, param_name, valid_value, invalid_value, weak_token, sql_payloads, xss_payloads))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

def main():
    print_logo()

    parser = argparse.ArgumentParser(description="Detector de Vulnerabilidades Avanzado en APIs")
    parser.add_argument("url", type=str, help="URL de la API a escanear")
    parser.add_argument("--param", type=str, help="Nombre del parámetro de la URL a analizar para IDOR")
    parser.add_argument("--valid_value", type=str, help="Valor válido del parámetro para IDOR")
    parser.add_argument("--invalid_value", type=str, help="Valor inválido del parámetro para IDOR")
    parser.add_argument("--weak_token", type=str, help="Token de autenticación para probar vulnerabilidad de autenticación débil")
    parser.add_argument("--sql_payloads", type=str, nargs='+', help="Payloads para pruebas de inyección SQL")
    parser.add_argument("--xss_payloads", type=str, nargs='+', help="Payloads para pruebas de XSS")
    parser.add_argument("--parallel", type=str, nargs='+', help="URLs de APIs a escanear en paralelo")

    args = parser.parse_args()

    if args.parallel:
        scan_api_in_parallel(args.parallel, args.param, args.valid_value, args.invalid_value, args.weak_token, args.sql_payloads, args.xss_payloads)
    else:
        scan_api(args.url, args.param, args.valid_value, args.invalid_value, args.weak_token, args.sql_payloads, args.xss_payloads)

if __name__ == "__main__":
    main()

