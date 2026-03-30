# Plugin for Exteragram - TG WebSocket Unblock
__id__ = "tgws_unblock"
__name__ = "TG WS Unblock"
__description__ = "Обход блокировки Telegram через WebSocket-туннель"
__icon__ = "tgws/1"
__author__ = "@exteraPluginsSup + by-sonic"
__version__ = "1.0.0"
__min_version__ = "12.1.1"

import threading
import time
import socket
import struct
import hashlib
import json
import re
import urllib.parse
import urllib.request
import urllib.error
from html import unescape

try:
    import ssl
except Exception:
    ssl = None

from base_plugin import BasePlugin, MenuItemData, MenuItemType, MethodHook
from android_utils import log, run_on_ui_thread
from android.graphics import Color
from ui.settings import Header, Switch, Selector, Text, Divider, Input
from ui.alert import AlertDialogBuilder
from java.util import Locale
from org.telegram.messenger import ApplicationLoader, SharedConfig, MessagesController, NotificationCenter
from org.telegram.tgnet import ConnectionsManager

# WebSocket endpoints для разных DC
DC_ENDPOINTS = {
    1: "wss://pluto.web.telegram.org/apiws",
    2: "wss://venus.web.telegram.org/apiws", 
    3: "wss://aurora.web.telegram.org/apiws",
    4: "wss://vesta.web.telegram.org/apiws",
    5: "wss://flora.web.telegram.org/apiws",
}

# DC маппинг по подсетям
DC_SUBNETS = [
    ("149.154.160.0", "149.154.163.255", 1),
    ("149.154.164.0", "149.154.167.255", 2),
    ("149.154.168.0", "149.154.171.255", 3),
    ("149.154.172.0", "149.154.175.255", 1),
    ("91.108.56.0", "91.108.59.255", 5),
    ("91.108.8.0", "91.108.11.255", 3),
    ("91.108.12.0", "91.108.15.255", 4),
    ("91.105.0.0", "91.105.255.255", 2),
    ("185.76.0.0", "185.76.255.255", 2),
]

LOCAL_PROXY_PORT = 10805
LOCAL_PROXY_HOST = "127.0.0.1"

TRANSLATIONS = {
    "settings_header": ("Настройки плагина", "Plugin settings"),
    "enable_plugin": ("Включить плагин", "Enable plugin"),
    "open_tg_settings": ("Настроить прокси", "Configure proxy"),
    "proxy_status": ("Статус прокси", "Proxy status"),
    "status_running": ("Работает", "Running"),
    "status_stopped": ("Остановлен", "Stopped"),
    "start_proxy": ("Запустить прокси", "Start proxy"),
    "stop_proxy": ("Остановить прокси", "Stop proxy"),
    "local_port": ("Локальный порт", "Local port"),
    "auto_config": ("Автонастройка", "Auto config"),
    "mode_ws": ("WebSocket туннель", "WebSocket tunnel"),
    "mode_direct": ("Прямое соединение", "Direct connection"),
    "select_mode": ("Режим работы", "Operation mode"),
    "connection_info": ("Информация о соединении", "Connection info"),
    "active_connections": ("Активные соединения", "Active connections"),
    "ws_tunnels": ("WS туннели", "WS tunnels"),
    "menu_settings": ("Настройки TG WS Unblock", "TG WS Unblock settings"),
}

def Z(key):
    lang = Locale.getDefault().getLanguage()
    idx = 0 if str(lang).startswith("ru") else 1
    try:
        return str(TRANSLATIONS.get(key, (key, key))[idx])
    except:
        return str(key)

def _prefs():
    return ApplicationLoader.applicationContext.getSharedPreferences("tgws_prefs", 0)

def _pget_int(k, d=0):
    try:
        return int(_prefs().getInt(k, int(d)))
    except:
        return d

def _pset_int(k, v):
    try:
        ed = _prefs().edit()
        ed.putInt(k, int(v))
        ed.commit()
    except:
        pass

def _pget_str(k, d=""):
    try:
        return str(_prefs().getString(k, str(d)) or "")
    except:
        return d

def _pset_str(k, v):
    try:
        ed = _prefs().edit()
        ed.putString(k, str(v or ""))
        ed.commit()
    except:
        pass

def _pget_bool(k, d=False):
    try:
        return bool(_prefs().getBoolean(k, bool(d)))
    except:
        return d

def _pset_bool(k, v):
    try:
        ed = _prefs().edit()
        ed.putBoolean(k, bool(v))
        ed.commit()
    except:
        pass

def ip_to_int(ip_str):
    """Конвертирует IP строку в integer"""
    try:
        parts = ip_str.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except:
        return 0

def get_dc_from_ip(ip_str):
    """Определяет DC по IP адресу"""
    try:
        ip_int = ip_to_int(ip_str)
        for subnet_start, subnet_end, dc in DC_SUBNETS:
            start_int = ip_to_int(subnet_start)
            end_int = ip_to_int(subnet_end)
            if start_int <= ip_int <= end_int:
                return dc
    except:
        pass
    return 2  # DC2 по умолчанию

def extract_dc_from_init(init_data):
    """Извлекает DC из obfuscated2 init пакета (64 байта)"""
    try:
        if len(init_data) < 64:
            return None
        
        # Ключ и IV для расшифровки
        key = init_data[8:40]
        iv = init_data[40:56]
        
        # Простая XOR дешифровка (упрощённая версия)
        decrypted = bytearray(64)
        for i in range(64):
            decrypted[i] = init_data[i] ^ key[i % 32]
        
        # DC ID находится в последних 4 байтах
        dc_id = struct.unpack('<i', bytes(decrypted[60:64]))[0]
        dc = abs(dc_id)
        
        if 1 <= dc <= 5:
            return dc
    except:
        pass
    return None

def is_telegram_ip(ip_str):
    """Проверяет, принадлежит ли IP к Telegram"""
    return get_dc_from_ip(ip_str) is not None

class ProxyServer:
    """Локальный SOCKS5 прокси сервер"""
    
    def __init__(self, host=LOCAL_PROXY_HOST, port=LOCAL_PROXY_PORT):
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False
        self.connections_count = 0
        self.ws_tunnels_count = 0
        self.lock = threading.Lock()
        self.active_sockets = []
    
    def start(self):
        """Запускает прокси сервер"""
        if self.running:
            return
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(50)
            self.server_socket.settimeout(1.0)
            
            self.running = True
            
            def serve():
                while self.running:
                    try:
                        client, addr = self.server_socket.accept()
                        with self.lock:
                            self.connections_count += 1
                        threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            log(f"Proxy accept error: {e}")
                        break
            
            threading.Thread(target=serve, daemon=True).start()
            log(f"TG WS Proxy started on {self.host}:{self.port}")
        except Exception as e:
            log(f"Failed to start proxy: {e}")
            self.running = False
    
    def stop(self):
        """Останавливает прокси сервер"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
        
        with self.lock:
            for sock in self.active_sockets[:]:
                try:
                    sock.close()
                except:
                    pass
            self.active_sockets.clear()
        
        log("TG WS Proxy stopped")
    
    def handle_client(self, client_socket, addr):
        """Обрабатывает клиентское SOCKS5 соединение"""
        try:
            client_socket.settimeout(10.0)
            
            with self.lock:
                self.active_sockets.append(client_socket)
            
            # Читаем приветствие клиента
            greeting = client_socket.recv(2)
            if len(greeting) < 2 or greeting[0] != 0x05:
                client_socket.close()
                return
            
            nmethods = greeting[1]
            methods = client_socket.recv(nmethods)
            
            # Отправляем ответ: no auth required
            client_socket.send(b'\x05\x00')
            
            # Читаем запрос на подключение
            request = client_socket.recv(256)
            if len(request) < 7:
                client_socket.close()
                return
            
            ver = request[0]
            cmd = request[1]
            
            if ver != 0x05 or cmd != 0x01:  # CONNECT command
                client_socket.send(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                return
            
            # Парсим адрес назначения
            addr_type = request[3]
            dest_addr = None
            dest_port = 0
            
            if addr_type == 0x01:  # IPv4
                if len(request) >= 10:
                    dest_addr = '.'.join(str(b) for b in request[4:8])
                    dest_port = struct.unpack('>H', request[8:10])[0]
            elif addr_type == 0x03:  # Domain name
                domain_len = request[4]
                if len(request) >= 5 + domain_len + 2:
                    dest_addr = request[5:5+domain_len].decode('utf-8', errors='ignore')
                    dest_port = struct.unpack('>H', request[5+domain_len:5+domain_len+2])[0]
            elif addr_type == 0x04:  # IPv6
                if len(request) >= 22:
                    dest_addr = ':'.join(format(request[4+i*2] << 8 | request[5+i*2], 'x') for i in range(8))
                    dest_port = struct.unpack('>H', request[20:22])[0]
            
            if not dest_addr:
                client_socket.send(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                client_socket.close()
                return
            
            # Отправляем успех
            response = b'\x05\x00\x00\x01\x7f\x00\x00\x01' + struct.pack('>H', self.port)
            client_socket.send(response)
            
            # Проверяем, это ли Telegram
            is_tg = is_telegram_ip(dest_addr) if addr_type == 0x01 else False
            
            if is_tg:
                # Читаем init пакет (64 байта)
                init_data = client_socket.recv(64)
                if len(init_data) == 64:
                    # Определяем DC
                    dc = extract_dc_from_init(init_data) or get_dc_from_ip(dest_addr) or 2
                    
                    with self.lock:
                        self.ws_tunnels_count += 1
                    
                    log(f"WS tunnel DC{dc} for {dest_addr}:{dest_port}")
                    
                    # Создаём WebSocket туннель
                    self.relay_via_websocket(client_socket, dc, init_data)
                    
                    with self.lock:
                        self.ws_tunnels_count -= 1
                else:
                    client_socket.close()
            else:
                # Для не-Telegram трафика - прямое подключение
                self.relay_direct(client_socket, dest_addr, dest_port)
            
        except Exception as e:
            log(f"Client handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            
            with self.lock:
                if client_socket in self.active_sockets:
                    self.active_sockets.remove(client_socket)
    
    def relay_direct(self, client_socket, dest_addr, dest_port):
        """Прямое TCP реле"""
        try:
            remote = socket.create_connection((dest_addr, dest_port), timeout=10)
            remote.setblocking(False)
            client_socket.setblocking(False)
            
            def forward(src, dst):
                try:
                    while self.running:
                        data = src.recv(4096)
                        if not data:
                            break
                        dst.sendall(data)
                except:
                    pass
            
            t1 = threading.Thread(target=forward, args=(client_socket, remote), daemon=True)
            t2 = threading.Thread(target=forward, args=(remote, client_socket), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            
            remote.close()
        except Exception as e:
            log(f"Direct relay error: {e}")
    
    def relay_via_websocket(self, client_socket, dc, init_data):
        """Реле через WebSocket туннель"""
        try:
            endpoint = DC_ENDPOINTS.get(dc, DC_ENDPOINTS[2])
            
            # Упрощённая реализация WebSocket клиента
            # В реальной реализации нужно использовать полноценную WebSocket библиотеку
            host = endpoint.replace("wss://", "").replace("/apiws", "")
            
            # Создаём SSL соединение
            context = ssl.create_default_context() if ssl else None
            if context:
                remote = context.wrap_socket(socket.create_connection((host, 443), timeout=10))
            else:
                remote = socket.create_connection((host, 443), timeout=10)
            
            # Формируем WebSocket handshake
            key = base64.b64encode(bytes([random.randint(0, 255) for _ in range(16)])).decode()
            
            handshake = (
                f"GET /apiws HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Protocol: binary\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            ).encode()
            
            remote.sendall(handshake)
            
            # Читаем ответ
            response = remote.recv(1024)
            
            if b"101" in response or b"Upgrade: websocket" in response:
                # Отправляем init данные
                remote.sendall(init_data)
                
                # Реле данных
                client_socket.setblocking(False)
                remote.setblocking(False)
                
                def forward_client_to_ws():
                    try:
                        while self.running:
                            data = client_socket.recv(4096)
                            if not data:
                                break
                            # WebSocket frame
                            frame = self.encode_ws_frame(data)
                            remote.sendall(frame)
                    except:
                        pass
                
                def forward_ws_to_client():
                    try:
                        buffer = b""
                        while self.running:
                            chunk = remote.recv(4096)
                            if not chunk:
                                break
                            buffer += chunk
                            
                            # Парсим WebSocket фреймы
                            while len(buffer) >= 2:
                                fin = (buffer[0] >> 7) & 1
                                opcode = buffer[0] & 0x0F
                                masked = (buffer[1] >> 7) & 1
                                payload_len = buffer[1] & 0x7F
                                
                                header_len = 2
                                if payload_len == 126:
                                    header_len = 4
                                elif payload_len == 127:
                                    header_len = 10
                                
                                if masked:
                                    header_len += 4
                                
                                if len(buffer) < header_len + payload_len:
                                    break
                                
                                if opcode == 0x1 or opcode == 0x2:  # Text or Binary
                                    payload = buffer[header_len:header_len+payload_len]
                                    if masked:
                                        mask = buffer[header_len-4:header_len]
                                        payload = bytes(payload[i] ^ mask[i % 4] for i in range(len(payload)))
                                    
                                    client_socket.sendall(payload)
                                
                                buffer = buffer[header_len+payload_len:]
                    except:
                        pass
                
                t1 = threading.Thread(target=forward_client_to_ws, daemon=True)
                t2 = threading.Thread(target=forward_ws_to_client, daemon=True)
                t1.start()
                t2.start()
                t1.join()
                t2.join()
            
            remote.close()
        except Exception as e:
            log(f"WS relay error DC{dc}: {e}")
    
    def encode_ws_frame(self, data, opcode=0x2):
        """Кодирует данные в WebSocket фрейм"""
        length = len(data)
        frame = bytearray()
        
        # FIN + opcode
        frame.append(0x80 | opcode)
        
        # Длина payload
        if length <= 125:
            frame.append(length)
        elif length <= 65535:
            frame.append(126)
            frame.extend(struct.pack('>H', length))
        else:
            frame.append(127)
            frame.extend(struct.pack('>Q', length))
        
        frame.extend(data)
        return bytes(frame)
    
    def get_stats(self):
        """Возвращает статистику"""
        with self.lock:
            return {
                "running": self.running,
                "connections": self.connections_count,
                "ws_tunnels": self.ws_tunnels_count,
                "active_sockets": len(self.active_sockets),
            }

class TGWSPlugin(BasePlugin):
    """Основной класс плагина"""
    
    def __init__(self):
        super().__init__()
        self.proxy_server = None
        self.enabled = False
        self.config_thread = None
    
    def on_plugin_load(self):
        """Инициализация плагина при загрузке"""
        self.enabled = _pget_bool("enabled", False)
        if self.enabled:
            self.start_proxy()
    
    def on_plugin_unload(self):
        """Очистка при выгрузке плагина"""
        self.stop_proxy()
    
    def start_proxy(self):
        """Запускает прокси сервер"""
        if self.proxy_server and self.proxy_server.running:
            return
        
        self.proxy_server = ProxyServer()
        self.proxy_server.start()
        self.enabled = True
        _pset_bool("enabled", True)
        
        # Автонастройка прокси в Telegram
        self.auto_configure_proxy()
    
    def stop_proxy(self):
        """Останавливает прокси сервер"""
        if self.proxy_server:
            self.proxy_server.stop()
            self.proxy_server = None
        
        self.enabled = False
        _pset_bool("enabled", False)
    
    def auto_configure_proxy(self):
        """Автоматически настраивает прокси в Telegram"""
        @run_on_ui_thread
        def configure():
            try:
                current = ConnectionsManager.getInstance().getCurrentProxy()
                if current:
                    address = current.get("address", "")
                    port = current.get("port", 0)
                    if address == LOCAL_PROXY_HOST and port == LOCAL_PROXY_PORT:
                        return
                
                # Настраиваем прокси
                proxy_dict = {
                    "address": LOCAL_PROXY_HOST,
                    "port": LOCAL_PROXY_PORT,
                    "username": "",
                    "password": "",
                    "type": 5  # SOCKS5
                }
                
                ConnectionsManager.getInstance().setProxy(proxy_dict, True)
                
                alert = AlertDialogBuilder(ApplicationLoader.applicationContext)
                alert.setTitle("TG WS Unblock")
                alert.setMessage("Прокси настроен автоматически!\n\nСервер: 127.0.0.1\nПорт: {}\n\nНажмите 'Подключить' в настройках Telegram.".format(LOCAL_PROXY_PORT))
                alert.setPositiveButton("OK", None)
                alert.show()
                
            except Exception as e:
                log(f"Auto config error: {e}")
        
        configure()
    
    def create_settings(self):
        """Создаёт экран настроек"""
        items = []
        
        items.append(Header(text=Z("settings_header")))
        
        # Вкл/выкл плагин
        items.append(Switch(
            key="enable",
            text=Z("enable_plugin"),
            default=self.enabled,
            on_change=lambda v: self.toggle_plugin(v)
        ))
        
        # Статус
        status = Z("status_running") if (self.proxy_server and self.proxy_server.running) else Z("status_stopped")
        items.append(Text(text=f"{Z('proxy_status')}: {status}", icon="msg_settings"))
        
        # Кнопки управления
        if self.proxy_server and self.proxy_server.running:
            items.append(Text(text=Z("stop_proxy"), icon="msg_stop", on_click=lambda v: self.stop_proxy()))
        else:
            items.append(Text(text=Z("start_proxy"), icon="msg_start", on_click=lambda v: self.start_proxy()))
        
        # Автонастройка
        items.append(Text(text=Z("auto_config"), icon="msg_link", on_click=lambda v: self.auto_configure_proxy()))
        
        # Статистика
        if self.proxy_server:
            stats = self.proxy_server.get_stats()
            items.append(Divider())
            items.append(Header(text=Z("connection_info")))
            items.append(Text(text=f"{Z('active_connections')}: {stats['connections']}", icon="msg_info"))
            items.append(Text(text=f"{Z('ws_tunnels')}: {stats['ws_tunnels']}", icon="msg_info"))
        
        items.append(Divider())
        items.append(Text(text=Z("open_tg_settings"), icon="msg_settings", on_click=lambda v: self._open_tg_proxy_settings()))
        
        return items
    
    def _open_tg_proxy_settings(self):
        """Открывает настройки прокси Telegram"""
        try:
            from org.telegram.ui import ProxyListActivity
            from client_utils import get_last_fragment
            frag = get_last_fragment()
            if frag:
                frag.presentFragment(ProxyListActivity())
        except Exception as e:
            log(f"Error opening proxy settings: {e}")
    
    def toggle_plugin(self, enabled):
        """Переключает состояние плагина"""
        if enabled:
            self.start_proxy()
        else:
            self.stop_proxy()
    
    def getMenuItems(self):
        """Возвращает пункты меню"""
        return [
            MenuItemData(
                "settings",
                Z("menu_settings"),
                lambda: self._open_settings()
            )
        ]
    
    def _open_settings(self):
        """Открывает настройки плагина через стандартный механизм Exteragram"""
        try:
            from com.exteragram.messenger.plugins import PluginsController
            PC = PluginsController.getInstance()
            if PC:
                try:
                    PC.openPluginSettings(self.id)
                    return
                except:
                    pass
            # Fallback: используем get_last_fragment
            from client_utils import get_last_fragment
            frag = get_last_fragment()
            if frag and PC:
                PC.getInstance().openPluginSettings(self.id, frag)
        except Exception as e:
            log(f"Error opening settings: {e}")
