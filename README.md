# FilzaJailedDS
Filza Jailed Darksword, support iOS 17.0-26.0.1 (except 18.7.2-18.7.7). This repo open source the tweak inject into the Filza iPA (4.0.0 and back, 4.0.2 seems crash something)
Now includes SSV-protected area write access with root privileges.

## Features
- Sandbox escape via kernel exploit
- Root helper bypass
- Zip/unzip hooks
- Bypass Filza padlock: lets you TRY to create and edit file even without permission
- License/integrity bypass
- **SSV-protected area write access**: Allows writing to system-protected areas like /System/Library/Keychains
- **Root privileges on created files**: Automatically chown files created in protected areas to root with write permissions

##  Known Issues
- Filza may take 2/3 tries before working (you can chek the logs on /tmp in the Filza sandbox)
- Bypass Filza padlock seems broken in some devices
- SSV-Bypass is still in development and may not work most of the time

About iPhone 17 series and iPad M5: IT WON'T WORK because of MTE. Starting from iPhone 17 and M5 chip, Apple added MTE to block anyone trying to access krw, so it will not work


# Credit
- Thanks to [Duy Tran](https://github.com/khanhduytran0) for the sandbox hook token
- Thanks to [wh1te4ever](https://github.com/wh1te4ever/) for the super details [darksword-kfun](https://github.com/wh1te4ever/darksword-kexploit-fun) with offset/XPF
- Thanks to [opa334](https://github.com/opa334/) for the XPF/krw
- Thanks to [CrazyMind90](https://github.com/crazymind90/) for idea how to get sbx token with krw only
- Thanks to [Huy Nguyen](https://github.com/34306/) for the original repo
- Thanks to [Grok](https://grok.com) and [Claude](https://claude.ai/) for assisting me with the implementation
- And me 
