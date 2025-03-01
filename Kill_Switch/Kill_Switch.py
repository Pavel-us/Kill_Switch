import tkinter as tk
import subprocess
import threading
import time

CHECK_INTERVAL = 0.5  # Интервал проверки VPN
UPDATE_INTERVAL = 0  # Интервал в секундах для автообновления интерфейсов (0 = ручное обновление)

# Функция для получения списка всех сетевых интерфейсов
def get_all_interfaces():
    interfaces = []
    output = subprocess.check_output("ip link show", shell=True).decode()
    for line in output.splitlines():
        if ": " in line:
            interface = line.split(":")[1].strip()
            interfaces.append(interface)
    return interfaces

# Функция для проверки существования интерфейса
def interface_exists(interface):
    try:
        subprocess.check_output(f"ip link show {interface}", shell=True).decode()
        return True
    except subprocess.CalledProcessError:
        return False

# Функция для блокировки всех интерфейсов, если VPN пропал
def block_all_internet():
    print("Блокировка всех интерфейсов. VPN отключен.")
    subprocess.run("sudo iptables -P OUTPUT DROP", shell=True)
    subprocess.run("sudo iptables -P FORWARD DROP", shell=True)
    subprocess.call(['notify-send', 'VPN Disconnect', 'VPN отключен! Доступ в интернет заблокирован.'])

# Функция для снятия всех блокировок
def unblock_all_internet():
    print("Разблокировка всех интерфейсов.")
    subprocess.run("sudo iptables -F OUTPUT", shell=True)
    subprocess.run("sudo iptables -P OUTPUT ACCEPT", shell=True)
    subprocess.run("sudo iptables -F FORWARD", shell=True)
    subprocess.run("sudo iptables -P FORWARD ACCEPT", shell=True)

# Функция для мониторинга VPN интерфейса
def monitor_vpn_interface(vpn_interface):
    global monitoring
    while monitoring:
        if not interface_exists(vpn_interface):
            print(f"Интерфейс {vpn_interface} пропал. Блокируем интернет.")
            block_all_internet()
            monitoring = False  # Останавливаем мониторинг без вызова stop_monitoring
            break
        time.sleep(CHECK_INTERVAL)

# Запуск мониторинга VPN интерфейса
def start_monitoring():
    global monitoring_thread, monitoring
    selected_interface = vpn_listbox.get(tk.ACTIVE)
    if selected_interface:
        if interface_exists(selected_interface):
            monitoring = True
            start_button.config(state=tk.DISABLED)
            stop_button.config(state=tk.NORMAL)
            vpn_listbox.config(state=tk.DISABLED)
            monitoring_thread = threading.Thread(target=monitor_vpn_interface, args=(selected_interface,))
            monitoring_thread.start()
            subprocess.call(['notify-send', 'Monitoring', f'Мониторинг VPN интерфейса {selected_interface} запущен.'])

# Остановка мониторинга VPN интерфейса
def stop_monitoring():
    global monitoring
    monitoring = False
    if monitoring_thread and monitoring_thread.is_alive():
        monitoring_thread.join()  # Ожидание завершения потока мониторинга
    unblock_all_internet()
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)
    vpn_listbox.config(state=tk.NORMAL)
    subprocess.call(['notify-send', 'Stopped', 'Мониторинг VPN интерфейса остановлен, доступ в интернет разблокирован.'])

# Функция для обновления списка VPN интерфейсов
def update_interfaces():
    vpn_listbox.delete(0, tk.END)  # Очищаем текущий список
    network_interfaces = get_all_interfaces()
    for interface in network_interfaces:
        vpn_listbox.insert(tk.END, interface)

# Функция для автообновления интерфейсов
def auto_update_interfaces():
    if UPDATE_INTERVAL > 0:
        update_interfaces()
        root.after(UPDATE_INTERVAL * 1000, auto_update_interfaces)  # Обновляем интерфейсы каждые N секунд

# Функция для обновления состояния кнопок
def update_buttons_state(event):
    if vpn_listbox.curselection():  # Если выбран интерфейс
        start_button.config(state=tk.NORMAL)
    else:
        start_button.config(state=tk.DISABLED)

# Главное окно
root = tk.Tk()
root.title("VPN Kill Switch")
root.configure(bg="#2E2E2E")  # Темный фон

# Настройка темной темы
root.tk_setPalette(background="#2E2E2E", foreground="#FFFFFF", activeBackground="#4B4B4B", activeForeground="#FFFFFF")

vpn_label = tk.Label(root, text="Доступные сетевые интерфейсы", bg="#2E2E2E", fg="#FFFFFF")
vpn_label.pack(pady=10)

# Список доступных сетевых интерфейсов
vpn_listbox = tk.Listbox(root, height=10, bg="#3A3A3A", fg="#FFFFFF", selectbackground="#4B4B4B", selectforeground="#FFFFFF")
vpn_listbox.pack()
vpn_listbox.bind("<<ListboxSelect>>", update_buttons_state)

# Кнопка обновления, если автообновление отключено
if UPDATE_INTERVAL == 0:
    update_button = tk.Button(root, text="Обновить", command=update_interfaces, bg="#3A3A3A", fg="#FFFFFF", activebackground="#4B4B4B", activeforeground="#FFFFFF")
    update_button.pack(pady=10)

# Кнопки для запуска и остановки мониторинга
button_frame = tk.Frame(root, bg="#2E2E2E")
button_frame.pack(pady=10)

start_button = tk.Button(button_frame, text="Запустить", command=start_monitoring, state=tk.DISABLED, bg="#3A3A3A", fg="#FFFFFF", activebackground="#4B4B4B", activeforeground="#FFFFFF")
start_button.grid(row=0, column=0, padx=5)

stop_button = tk.Button(button_frame, text="Остановить", command=stop_monitoring, state=tk.DISABLED, bg="#3A3A3A", fg="#FFFFFF", activebackground="#4B4B4B", activeforeground="#FFFFFF")
stop_button.grid(row=0, column=1, padx=5)

monitoring = False
monitoring_thread = None

# Автоматическое обновление списка интерфейсов при запуске, если не задано ручное обновление
if UPDATE_INTERVAL > 0:
    auto_update_interfaces()
else:
    update_interfaces()

# При закрытии программы разблокируем все интерфейсы
def on_closing():
    stop_monitoring()  # Останавливаем мониторинг и разблокируем интернет
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

root.mainloop()
