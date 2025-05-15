# PP4

## Goal

In this exercise you will:

* Use SSH to connect to remote servers from WSL, macOS, or Linux shells, understanding the handshake and authentication process.
* Generate an Ed25519 SSH key pair and explain the concept of digital signatures.
* Configure your local SSH client via the `~/.ssh/config` file for streamlined access.
* Securely copy files between local and remote hosts using `scp`, including local-to-remote, remote-to-local, and remote-to-remote transfers.
* Automate startup tasks on the remote server by writing a shell script that runs at login and explaining the role of `~/.bashrc` vs. `~/.profile`.

**Important:** Start a stopwatch when you begin and work uninterruptedly for **90 minutes**. Once time is up, stop immediately and record exactly where you paused.

---

## Workflow

1. **Fork** this repository
2. **Modify & commit** your solution
3. **Submit your link for Review**

---

## Prerequisites

* Several starter repos are available here:
  [https://github.com/orgs/STEMgraph/repositories?q=SSH%3A](https://github.com/orgs/STEMgraph/repositories?q=SSH%3A)
* Consult the SSH and SCP man-pages for detailed options and explanations:

  * `man ssh`
  * `man scp`

---

## Tasks

### Task 1: SSH Login

**Objective:** Establish an SSH connection and observe each stage of the process.

1. From your local shell (WSL, macOS Terminal, or Linux), log into the `vorlesungsserver` (or any other remote machine of your choice, e.g. your own raspberry pi):

   ```bash
   ssh youruser@remotehost
   ```
2. Carefully observe and note each step:

   * **TCP connection** to port 22 on `remotehost`.
   * **SSH protocol handshake**: key exchange and algorithm negotiation.
   * **Authentication**: public-key or password exchange.
   * **Shell allocation**: your remote session starts.
3. After login, exit the session with `exit`.

**Provide:**

```bash
# 1) The exact ssh command you ran
# 2) A detailed, step-by-step explanation of what happened at each stage
```
## 1)

192.168.178.56maxm@FractalDesignR6:~$ ssh maxm2@192.168.178.56

## 2)

**Schritt 1: TCP-Verbindung**

Die TCP Verbindung wird aufgebaut (3-Way Handshake)
Nachdem ich den Befehl "ssh maxm2@192.168.178.56" 
auf meinem WSL-Terminal (FractalDesignR6) eingegeben habe, hat mein Computer versucht, eine TCP-Verbindung zum Zielgerät (Laptop mit WSL mit der IP-Adresse 192.168.178.56) über Port 22 herzustellen.
Diese Verbindung wurde mit dem sogenannten TCP 3 Wege Handschlag (SYN, SYN-ACK, ACK) aufgebaut.
Wenn dies erfolgt ist, war die Verbindung auf TCP-Ebene erfolgreich und bereit für die SSH-Kommunikation.

**Schritt 2: SSH-Protokoll-Handshake**

Ist die TCP Verbindung erfolgreich wird das SSH Protokoll mit einem so genannten Handshake eingeleitet; Client (hier FractalDesignR6) und Server (XPS 15 Laptop) "einigen" sich gemeinsame auf Verschlüsselungsverfahren, Authentifizierungsmethoden. Außerdem sendet der Server den öffentlichen Hostschlüssel an den Client. Dieser prüft, ob der Schlüssel bereits in der Datei known_hosts gespeichert ist. Wenn der Schlüssel neu oder verändert ist, werde ich entsprechend gewarnt bzw gefragt, ob ich ihm vertraue.

**Schritt 3: Authentifizierung**

Da dies mein erster Versuch mit SSh ist, habe ich entsprechend keinen SSH-Schlüssel, daher erfolgt die Authentifizierung über die Eingabe eines Passworts. Der SSH-Server (XPS 15) fordert das Passwort für den Benutzer maxm2 an,welches ich im Anschluss eingegeben habe. Erst wenn das Passwort akzeptiert wird, bin ich authentifiziert.


**Schritt 4: Shell-Zuweisung**

Nach erfolgreicher Authentifizierung/Anmeldung weist der Server (XPS 15) mir eine interaktive Shell zu. Ich sehe dann das Powershellterminal (cmd.exe) meines Laptops. Da mein Laptop ebenfalls eine Ubuntu-WSl besitzt kann ich nun über den Befehl wsl.exe auf das Terminal zugreifen (maxm@XPS-15-9520:/mnt/c/Users/maxm2$)


---

### Task 2: Ed25519 Key Pair

**Objective:** Create a secure key pair and explain how digital signatures verify identity.

1. Generate an Ed25519 SSH key pair:

   ```bash
   ssh-keygen -t ed25519 -C "your_email@example.com"
   ```

   * Accept the default file location (`~/.ssh/id_ed25519`). Or provide the `-f <filepath>` option additionally.
   * Enter a passphrase when prompted (optional).
2. Locate and inspect your `id_ed25519` (private key) and `id_ed25519.pub` (public key).
3. Install your key on the remote machine (e.g. `vorlesungsserver`.
4. Explain in writing:

   * How the **private key** is used to sign challenges.
   * How the **public key** on the server verifies signatures without revealing the private key.
   * Why Ed25519 is preferred (performance, security).

**Provide:**

```bash
# 1) The ssh-keygen command you ran
# 2) The file paths of the generated keys
# 3) Your written explanation (3–5 sentences) of the signature process
```
## 1)

maxm@XPS-15-9520:/mnt/c/Users/maxm2$ ssh-keygen -t ed25519 -C maxm2@ssh

## 2)

maxm@XPS-15-9520:/mnt/c/Users/maxm2$ ls -l ~/.ssh/id_ed25519 ~/.ssh/id_ed25519.pub

-rw------- 1 maxm maxm 444 May 15 15:33 /home/maxm/.ssh/id_ed25519

-rw-r--r-- 1 maxm maxm  91 May 15 15:33 /home/maxm/.ssh/id_ed25519.pub

## 3)

Der private Schlüssel wird für den Anmeldeprozess genutzt, um eine kryptografische "Herausforderung" (im eng. Challenge) zu signieren. Währendessen  wird eine Signatur erzeugt, die einzig und alleine mit dem privaten Schlüssel erzeugt werden kann. Der öffentlichen Schlüssel, auf dem Server ist in der Lage diese Signatur zu überprüfen, ohne den privaten Schlüssel zu kennen. Dadurch kann Server sicher bestätigen, dass die Verbindung vom Besitzer des privaten Schlüssels kommt. 
Die Verschlüsselung Ed25519 wird bevorzugt verwendet, da diese moderne kryptografische Algorithmen nutzt, welche als besonders schnell, sicher und resistent gegen verschiedene Angriffe gelten.

---

### Task 3: SSH Config File

**Objective:** Simplify SSH commands via `~/.ssh/config`.

1. Open (or create) `~/.ssh/config` in `vim`.
2. Add entries for your hosts, for example:

   ```text
   Host my-remote
       HostName remote.example.com
       User youruser
       IdentityFile ~/.ssh/id_ed25519

   Host backup-server
       HostName backup.example.com
       User backupuser
       Port 2222
       IdentityFile ~/.ssh/id_ed25519_backup
   ```
3. Save and close the file, then test:

   ```bash
   ssh my-remote
   ssh backup-server
   ```
4. Explain:

   * How SSH reads `~/.ssh/config` and matches hosts.
   * The difference between `HostName` and `Host`.
   * How aliases prevent long commands.

**Provide:**

```text
# 1) The full contents of your ~/.ssh/config
# 2) A short explanation (3–4 sentences) of how the config simplifies connections
```
## 1)

Host xps15
    HostName 192.168.178.56
    User maxm2
    IdentityFile ~/.ssh/id_ed25519

## 2)

Die Datei ~/.ssh/config wird beim Aufruf von ssh gelesen, falls der zuvor eingegebene Name mit den Daten aus  der ~/.ssh/config übereinstimmt, werden die darin enthaltenen Parameter wie HostName (IP), User (Benutzername) und IdentityFile (Schlüsseldatei) verwendet.

Host ist ein Spitzname oder Kürzel, dass bei dem ssh-Befehl verwendet werden kann (z.B. in meinem Fall "ssh xps15" )

HostName ist die tatsächliche IP-Adresse, zu der die Verbindung aufgebaut wird.

Durch die Verwendung eines Kürzels oder Spitznamen nach ssh, kann dieser Befehl viel einfach und fehlerfreier eingegeben werden:

"ssh maxm2@192.168.178.56 -i ~/.ssh/id_ed25519" wird dann zu "ssh xps15"

---

### Task 4: SCP File Transfers

**Objective:** Practice copying files securely using `scp`.

1. **Local → Remote**:

   ```bash
   scp /path/to/localfile.txt youruser@remotehost:~/destination/
   ```
2. **Remote → Local**:

   ```bash
   scp youruser@remotehost:~/remotefile.log ./local_destination/
   ```
3. **Remote → Remote** (between two directories on the same remote host):

   ```bash
   scp -r youruser@remotehost:/path/dir1 youruser@remotehost:/path/dir2
   ```
4. For each command:

   * Verify file timestamps and sizes after transfer, using `ls -la`
   * Note any flags you used (e.g., `-r`, `-P` for port).
5. Explain:

   * How `scp` initiates an SSH session for each transfer.
   * The role of encryption in protecting data in transit.

**Provide:**

```bash
# 1) Each scp command you ran
# 2) Any flags or options used
# 3) A brief explanation (2–3 sentences) of scp’s mechanism
```
## 1)

Lokale Datei → Remote (Laptop)
scp ~/scp_test/testfile.txt maxm2@192.168.178.56:~/scp_test/

Remote (Laptop) → Lokal
scp maxm2@192.168.178.56:~/scp_test/testfile.txt ~/scp_test/

Remote  → Remote

scp maxm2@192.168.178.56:~/scp_test/testfile.txt maxm2@192.168.178.56:~/

## 2)

Es wurden keine weiteren Flags oder Optionen verwendet

## 3)

scp startet im Hintergrund eine SSH Sitzung, dadurch können Dateien sicher zwischen zwei Hosts übertragen werden, scp überträgt Dateien verschlüsselt und schützt dabei sowohl die Inhalte als auch die Dateinamen. Die Verbindung ist genauso abgesichert wie bei SSH, was SCP zu einer sicheren Methode für Dateitransfers macht. ---


### Task 5: Login Shell Script & Profile Explanation

**Objective:** Automate commands at login and understand shell initialization files.

1. On the **remote** server, create a script `~/login_tasks.sh` containing at least three commands you find useful (e.g., `echo "Welcome $(whoami)"`, `uptime`, `ls ~/projects`). You may either use `vim` or try the following to create a file from your commandline directely:

   ```bash
   cat << 'EOF' > ~/login_tasks.sh
   #!/usr/bin/env bash
   echo "Welcome $(whoami)! Today is $(date)."
   uptime
   ls ~/projects
   EOF
   chmod +x ~/login_tasks.sh
   ```

> The files content should be something akin to:
> ```bash
> #!/usr/bin/env bash
> echo "Welcome $(whoami)! Today is $(date)."
> uptime
> ls ~/projects
> ```

2. Append to your `~/.bashrc` (or `~/.profile` if using a login shell) a line to source this script on each new session:

   ```bash
   echo "source ~/login_tasks.sh" >> ~/.bashrc
   ```
3. Log out and log back in to trigger the script.
4. Explain:

   * The difference between `~/.bashrc` and `~/.profile` (interactive vs. login shells).
   * Why and when each file is read.
   * How sourcing differs from executing.

**Provide:**

```bash
# 1) The contents of login_tasks.sh
# 2) The lines you added to ~/.bashrc or ~/.profile
# 3) Your explanation (3–5 sentences) of shell init files and sourcing vs. executing
```
## 1)  

#!/usr/bin/env bash
echo "Welcome $(whoami)! Today is $(date)."
uptime
ls ~/projects

## 2) 

source ~/login_tasks.sh

## 3)

source ~/login_tasks.shfindet Anwendung bei bereits aktiven SSH Sitzungen, wie z.B. das öffnen eines weiteren Terminals in einer bereits eingeloggten SSH Sitzung, Dahingegen findet ~/.profile Verwendung in Login-Shells (z.B. das Einloggen via SSH).
Wird source ~/login_tasks.sh in source ~/login_tasks.sh hinzugefügt, so wird das enthaltene Skript von source direkt bei Beginn der Sitzung automatisch gestartet und angezeigt (in diesem Falls das Besispiel 
"Welcome maxm! Today is ...)

In dem Fall von Sourcing, wird das Skript (hier source ~/login_tasks.sh) in der aktuellen Shell ausgeführt. Bei 
Executing hingegen, wird das Skript in einem Unterprozess (eng. subshell) geladenund beinflusst die aktuelle Shell Sitzung nicht.

---

**Remember:** Stop working after **90 minutes** and record where you stopped.
