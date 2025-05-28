import subprocess
import datetime
import os
import paramiko
import getpass

# --- 0. Fájlelérési alap: szkript helye ---
script_dir = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(script_dir, "log")
os.makedirs(log_dir, exist_ok=True)

input1 = os.path.join(log_dir, "s1-eth1_in.pcap")
input2 = os.path.join(log_dir, "s1-eth1_out.pcap")
merged = os.path.join(log_dir, "output_merged.pcap")

# --- 1. mergecap ---
result = subprocess.run(
    ["mergecap", "-w", merged, input1, input2],
    check=True,
    capture_output=True,
    text=True
)

# --- 2. átnevezés időbélyeggel ---
now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
final_name = os.path.join(log_dir, f"merged_{now}.pcap")
os.rename(merged, final_name)

# --- 3. SFTP feltöltés (rejtett jelszó) ---
hostname = 'caesar.elte.hu'
port = 22
username = 'sandorbalazs'
remote_path = '/afs/elte.hu/user/s/sandorbalazs/web/tcp'

password = getpass.getpass("Add meg az SFTP jelszót (nem látszik gépelés közben): ")

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname, port=port, username=username, password=password)

sftp = ssh.open_sftp()
sftp.chdir(remote_path)
# Külön a helyi teljes elérési út, és a szerveren csak a fájlnév!
sftp.put(final_name, os.path.basename(final_name))
sftp.close()
ssh.close()

print(f"Sikeres összefűzés és SFTP feltöltés: {remote_path}/{os.path.basename(final_name)}")
