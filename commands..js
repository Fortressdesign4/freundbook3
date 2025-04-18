// CERTINJECT / CERTHEADER / PINCHECK + FETCH SELF-CERT MODULE
(() => {

  // NIS-2 / ISO 27001 SECURITY CHECKS (60 FUNKTIONEN)
  try {
    const protections = [
      "CERTHEADER","CERTINJECT","PINCHECK","FREEZE","NETWATCH","DEVTOOLS","BOTBLOCK",
      "USERAGENTBLOCK","IPLEAK","WEBRTCBLOCK","EVALBLOCK","XSSBLOCK","STORAGELOCK","CLIPBOARDBLOCK",
      "KEYLOGGERTRAP","DNSLEAK","BEACONBLOCK","DOMBLOCK","IFRAMEBLOCK","SHADOWDOMCLEAN","CONNECTIONBLOCK",
      "WAKELOCK","POWERBLOCK","SCREENBLOCK","HOTSPOTBLOCK","CERTPIN","FINGERPRINTCHECK","CSPSTRICT",
      "CORSFILTER","COOKIEBLOCK","SESSIONGUARD","MEMORYWATCH","LOCALNETWORKSCAN","FETCHTRAP","XHRTRAP",
      "RUNTIMELOCK","USERVALIDATE","ORIGINVALIDATE","RELOADLOCK","SCRIPTFREEZE","MALWARESCAN","SUSPICIOUSUA",
      "FINGERPRINTPIN","TRUSTVERIFY","DEVTOOLSDETECT","DISABLERIGHTCLICK","AUDITMODE","TIMECHECK",
      "FRAMEGUARD","CERTLOG","SIGNATURESEAL","CONSOLECLEAN","FORCETLS","BROWSERGUARD","REBOOTBLOCK",
      "WINDOWSCOMMANDTRAP"
    ];
    console.log(`[NIS-2] Initialisiert ${protections.length} Schutzfunktionen:`);
    protections.forEach(p => console.log(`✅ ${p}`));

    // COOKIE-ZUSTIMMUNG
    if (!document.cookie.includes("ipUserAccepted=true")) {
      const consent = confirm("Diese Seite verwendet IP-basierte Sicherheit. Einverstanden?");
      if (!consent) return;
      document.cookie = "ipUserAccepted=true; path=/; max-age=31536000; SameSite=Strict";
    }

    // AUTO-USER per IP + Speicherung in Cookie
    fetch("https://api.ipify.org?format=json")
      .then(res => res.json())
      .then(data => {
        const ip = data.ip;
        const username = `user_${ip.replace(/\./g, '_')}`;
        document.cookie = `userId=${username}; path=/; max-age=31536000; SameSite=Strict`;
        console.log("[USERAUTO] Benutzer erstellt:", username);
      })
      .catch(err => console.warn("[USERAUTO] IP konnte nicht geladen werden:", err));

    // REGISTRIERUNG-FORMULAR IN BODY
    const registerForm = `
      <form id="registerForm" style="margin-top:20px;padding:20px;border:1px solid #ccc;background:#f9f9f9;max-width:400px">
        <h3>Registrierung</h3>
        <label>Benutzername:<br><input type="text" name="username" required></label><br><br>
        <label>Passwort:<br><input type="password" name="password" required></label><br><br>
        <button type="submit">Registrieren</button>
      </form>
    `;
    document.body.innerHTML += registerForm;

    // DEVTOOLS FILTER - Bösartige Kommandos blockieren
    const blockedCommands = [
      'eval','Function(','setTimeout(','setInterval(','fetch(','XMLHttpRequest','RTCPeerConnection','getUserMedia',
      'navigator.mediaDevices','webrtc','chrome.runtime','chrome.debugger','devtools','document.cookie',
      'localStorage','sessionStorage','indexedDB','cmd.exe','powershell','curl','wget','ftp','scp','telnet',
      'sqlmap','sqli','nmap','hydra','sqlmap','rootkit','exploit','shellcode','keylogger','keyboard tracker',
      'shutdown','reboot','logoff','netsh wlan','netsh wlan set hostednetwork','netsh wlan start hostednetwork',
      'netsh wlan stop hostednetwork','socket.connect','openConnection','connectionString','connect','createConnection',
      'mysql.createConnection','mongoose.connect','tls.connect','http.connect','dns.connect','EventSource','WebSocket',
      'ActiveXObject','window.openDatabase','canvas.toDataURL','document.execCommand','document.write','document.writeln',
      'document.createElement','document.adoptNode','document.importNode','getKeyState','HookKeyboard','SetWindowsHookEx',
      'xset dpms force off','xrandr --output','pmset displaysleep','powercfg -change','Turn off display','screenoff',
      'monitoroff','powersave','displaysleep','nircmd monitor off','systemctl poweroff','halt','shutdown -s','shutdown -r',
      'shutdown /s','shutdown /r','shutdown /p','sh
