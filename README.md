# ⣿⣿⡿⠋⠄⡀⣿⣿⣿⣿⣿⣿⣿⠿⠛⠋⣉⣉⣉⡉⠙⠻
# ⣿⣿⣇⠔⠈⣿⣿⣿⣿⡿⠛⢉⣤⣶⣾⣿⣿⣿⣿⣿⣿⣦
# ⣿⠃⠄⢠⣾⣿⣿⠟⢁⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
# ⣿⣿⣿⣿⣿⠟⢁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
# ⣿⣿⣿⡟⠁⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
# ⣿⣿⠋⢠⣾⣿⣿⣿⣿⣿⣿⡿⠿⠿⠿⠿⣿⣿⣿⣿⣿⣿
# ⡿⠁⣰⣿⣿⣿⣿⣿⣿⣿⣿⠗⠄⠄⠄⠄⣿⣿⣿⣿⣿⣿
# ⠁⣼⣿⣿⣿⣿⣿⣿⡿⠋⠄⠄⠄⣠⣄⢰⣿⣿⣿⣿⣿⣿
# ⣼⣿⣿⣿⣿⣿⣿⡇⠄⢀⡴⠚⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿
# ⢰⣿⣿⣿⣿⣿⡿⣿⣿⠴⠋⠄⠄⢸⣿⣿⣿⣿⣿⣿⣿⡟
# ⣿⣿⣿⣿⣿⣿⠃⠈⠁⠄⠄⢀⣴⣿⣿⣿⣿⣿⣿⣿⡟⢀
# ⣿⣿⣿⣿⣿⣿⠄⠄⠄⠄⢶⣿⣿⣿⣿⣿⣿⣿⣿⠏⢀⣾
# ⣿⣿⣿⣿⣿⣷⣶⣶⣶⣶⣶⣿⣿⣿⣿⣿⣿⣿⠋⣠⣿⣿
# ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢁⣼⣿⣿⣿
# ⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢁⣴⣿⣿⣿⣿⣿
# ⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⢁⣴⣿⣿⣿⠗⠄⠄⣿
# ⠈⠻⣿⣿⣿⣿⣿⠿⠛⣉⣤⣾⣿⣿⣿⣿⣇⠠⠺⣷⣿
# ⣦⣄⣈⣉⣉⣉⣡⣤⣶⣿⣿⣿⣿⣿⣿⣿⠉⠁⣀⣼⣿⣿

from scapy.all import ARP, Ether, srp, sniff
import socket
import time

# وظيفة لاكتشاف الأجهزة في الشبكة
def discover_devices(network_range):
    arp_request = ARP(pdst=network_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=2, verbose=False)

    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    return devices

# وظيفة لمراقبة حركة المرور في الشبكة
def monitor_traffic(packet):
    if packet.haslayer("IP"):
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        print(f"Network Traffic: {ip_src} -> {ip_dst}")

# وظيفة لفك تشفير كلمات المرور عبر SSH (قوة عمياء)
def password_cracker(target_ip, username, password_list):
    for password in password_list:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, 22))  # نفترض أن SSH يعمل على المنفذ 22
        if result == 0:
            print(f"Trying {username}:{password}")
            # هنا يمكنك تنفيذ منطق التحقق الفعلي من كلمة المرور
        sock.close()

# وظيفة لإنشاء قائمة كلمات المرور
def create_password_list():
    common_passwords = ['123456', 'password', '123456789', '12345678', '12345']
    with open('password_list.txt', 'w') as f:
        for password in common_passwords:
            f.write(password + '\n')
    print("Password list created.")

# تشغيل السكربت في النظام
if __name__ == "__main__":
    network_range = "192.168.1.0/24"  # النطاق الشبكي
    print("Starting device discovery...")
    devices = discover_devices(network_range)
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

    print("\nStarting network traffic monitoring...")
    sniff(filter="ip", prn=monitor_traffic, store=0)  # مراقبة حركة المرور

    target_ip = "192.168.1.1"  # عنوان الهدف للاختبار
    username = "admin"  # اسم المستخدم
    create_password_list()

    # تحميل كلمات المرور من الملف
    with open('password_list.txt', 'r') as f:
        password_list = f.read().splitlines()

    print("\nStarting password cracking...")
    password_cracker(target_ip, username, password_list)
