import tkinter as tk
from tkinter import ttk
import subprocess
import threading
import time

CHECK_INTERVAL = 0.5  # Интервал проверки

# Глобальная переменная для контроля состояния мониторинга
monitoring = False
monitoring_thread = None

# Функция для получения списка всех сетевых интерфейсов
def get_all_interfaces():
    interfaces = []
    output = subprocess.check_output("ip link show", shell=True).decode()
    for line in output.splitlines():
        if ": " in line:
            interface = line.split(":")[1].strip()
            interfaces.append(interface)
    return interfaces

# Функция для получения списка IP-адресов для интерфейсов
def get_all_ips():
    ips = []
    output = subprocess.check_output("ip -4 addr show", shell=True).decode()
    for line in output.splitlines():
        if "inet " in line:
            ip = line.split()[1].split("/")[0]
            ips.append(ip)
    return ips

# Функция для получения локальных IP-адресов и портов через netstat -ntulp
def get_local_ips_and_ports():
    local_ips_ports = set()
    output = subprocess.check_output("netstat -ntulp", shell=True).decode()
    for line in output.splitlines():
        if "0.0.0.0" in line or "127.0.0.1" in line:
            parts = line.split()
            if len(parts) > 3:
                ip_port = parts[3]  # Получаем адрес в формате IP:PORT
                local_ips_ports.add(ip_port)  # Добавляем в множество
    return list(local_ips_ports)

# Функция для проверки существования интерфейса
def interface_exists(interface):
    try:
        subprocess.check_output(f"ip link show {interface}", shell=True).decode()
        return True
    except subprocess.CalledProcessError:
        return False

# Функция для блокировки всех интерфейсов
def block_all_internet():
    print("Блокировка всех интерфейсов.")
    subprocess.run("sudo iptables -P OUTPUT DROP", shell=True)
    subprocess.run("sudo iptables -P FORWARD DROP", shell=True)
    subprocess.call(['notify-send', 'VPN Disconnect', 'Интернет заблокирован.'])
    update_interfaces_and_ips()  # Обновляем интерфейсы и IP-адреса при блокировке

# Функция для снятия всех блокировок
def unblock_all_internet():
    print("Разблокировка всех интерфейсов.")
    subprocess.run("sudo iptables -F OUTPUT", shell=True)
    subprocess.run("sudo iptables -P OUTPUT ACCEPT", shell=True)
    subprocess.run("sudo iptables -F FORWARD", shell=True)
    subprocess.run("sudo iptables -P FORWARD ACCEPT", shell=True)
    update_interfaces_and_ips()  # Обновляем интерфейсы и IP-адреса при разблокировке

# Функция для мониторинга интерфейсов и IP-адресов
def monitor_vpn_interface(vpn_interface, monitored_ips):
    global monitoring
    while monitoring:
        # Проверяем, существует ли интерфейс
        if not interface_exists(vpn_interface):
            print(f"Интерфейс {vpn_interface} пропал. Обновляем список.")
            block_all_internet()
            update_interfaces_and_ips()
            monitoring = False
            break

        # Проверяем IP-адреса, если отмечены
        for ip in monitored_ips:
            current_ips = get_all_ips() + get_local_ips_and_ports()  # Объединяем обычные и локальные IP
            if ip not in current_ips:
                print(f"IP {ip} пропал или изменился. Блокировка интернета.")
                block_all_internet()
                monitoring = False
                break

        time.sleep(CHECK_INTERVAL)

# Запуск мониторинга VPN интерфейса
def start_monitoring():
    global monitoring_thread, monitoring
    if monitoring:
        # Если мониторинг уже запущен, выводим предупреждение
        subprocess.call(['notify-send', 'Уведомление', 'Мониторинг уже запущен.'])
        return

    selected_interface = vpn_listbox.get(tk.ACTIVE)
    selected_ips = [ip_listbox.get(i) for i in ip_listbox.curselection()]  # Отмеченные IP

    if selected_interface:
        if interface_exists(selected_interface):
            monitoring = True
            start_button.config(state=tk.DISABLED)
            stop_button.config(state=tk.NORMAL)
            update_button.config(state=tk.DISABLED)  # Отключаем кнопку обновления во время мониторинга
            vpn_listbox.config(state=tk.DISABLED)

            # Уведомление о запуске мониторинга
            if selected_ips:  # Мониторинг по IP
                subprocess.call(['notify-send', 'Monitoring', f'Мониторинг IP-адресов {", ".join(selected_ips)} запущен.'])
            else:  # Мониторинг по интерфейсу
                subprocess.call(['notify-send', 'Monitoring', f'Мониторинг VPN интерфейса {selected_interface} запущен.'])

            # Запускаем мониторинг в отдельном потоке
            monitoring_thread = threading.Thread(target=monitor_vpn_interface, args=(selected_interface, selected_ips))
            monitoring_thread.start()

# Остановка мониторинга VPN интерфейса
def stop_monitoring():
    global monitoring
    monitoring = False
    if monitoring_thread and monitoring_thread.is_alive():
        monitoring_thread.join()  # Ожидание завершения потока мониторинга
    unblock_all_internet()
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    update_button.config(state=tk.NORMAL)  # Включаем кнопку обновления после остановки
    vpn_listbox.config(state=tk.NORMAL)
    update_interfaces_and_ips()  # Обновляем список интерфейсов и IP после остановки
    subprocess.call(['notify-send', 'Stopped', 'Мониторинг VPN интерфейса остановлен, доступ в интернет разблокирован.'])

# Функция для обновления списка VPN интерфейсов и IP адресов
def update_interfaces_and_ips():
    vpn_listbox.delete(0, tk.END)  # Очищаем текущий список
    ip_listbox.delete(0, tk.END)  # Очищаем список IP

    # Обновляем список интерфейсов
    network_interfaces = get_all_interfaces()
    for interface in network_interfaces:
        vpn_listbox.insert(tk.END, interface)

    # Обновляем список IP-адресов (обычные + локальные)
    ip_addresses = get_all_ips() + get_local_ips_and_ports()
    for ip in ip_addresses:
        ip_listbox.insert(tk.END, ip)

# Функция для завершения работы программы
def on_closing():
    global monitoring
    if monitoring:
        # Остановить мониторинг и разблокировать интернет перед закрытием
        stop_monitoring()
    else:
        # Если мониторинг не запущен, просто снимаем блокировки
        unblock_all_internet()
    root.destroy()  # Закрывает окно и завершает работу программы

# Главное окно
root = tk.Tk()
root.title("VPN Kill Switch")
root.configure(bg="#2E2E2E")  # Темный фон
root.geometry("290x420")  # Возвращаем стандартный размер окна
root.minsize(290, 420)  # Минимальный размер окна

# Устанавливаем обработчик для закрытия окна
root.protocol("WM_DELETE_WINDOW", on_closing)

# Настройка темной темы
style = ttk.Style()
style.configure("TLabel", background="#2E2E2E", foreground="#FFFFFF")
style.configure("TCheckbutton", background="#2E2E2E", foreground="#FFFFFF")
style.configure("TButton", background="#3A3A3A", foreground="#FFFFFF")
style.configure("TFrame", background="#2E2E2E")
style.configure("TListbox", background="#3A3A3A", foreground="#FFFFFF")
style.configure("TListbox.Highlight", background="#FFFFFF", foreground="#000000")  # Белое выделение

vpn_label = ttk.Label(root, text="Доступные сетевые интерфейсы")
vpn_label.pack(pady=5)

# Список доступных сетевых интерфейсов
vpn_listbox = tk.Listbox(root, height=5, bg="#3A3A3A", fg="#FFFFFF", selectbackground="#FFFFFF", selectforeground="#000000")
vpn_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

# Список IP адресов (обычные + локальные)
ip_label = ttk.Label(root, text="Доступные IP адреса")
ip_label.pack(pady=5)

ip_listbox = tk.Listbox(root, height=5, bg="#3A3A3A", fg="#FFFFFF", selectbackground="#FFFFFF", selectforeground="#000000", selectmode=tk.MULTIPLE)
ip_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

# Панель для кнопок "Запустить", "Обновить", "Остановить"
button_frame = ttk.Frame(root)
button_frame.pack(pady=10)

start_button = ttk.Button(button_frame, text="Запустить", command=start_monitoring)
start_button.pack(side=tk.LEFT, padx=10)

update_button = ttk.Button(button_frame, text="Обновить", command=update_interfaces_and_ips)
update_button.pack(side=tk.LEFT, padx=10)

stop_button = ttk.Button(button_frame, text="Остановить", command=stop_monitoring, state=tk.DISABLED)
stop_button.pack(side=tk.LEFT, padx=10)

# Начальная настройка и запуск
update_interfaces_and_ips()

root.mainloop()
