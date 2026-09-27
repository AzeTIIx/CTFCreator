# themes/

Themes CTFd vendus dans ce dépôt (pas de suivi automatique de `main`).

## pixo (actif)

- Source : https://github.com/hmrserver/CTFd-theme-pixo
- Commit épinglé : voir `PIN.txt`
- Monté dans Compose : `/opt/CTFd/CTFd/themes/pixo`
- Activation admin : **Admin Panel > Config > Themes > pixo > Update**

### Attention

Le README amont déclare une compatibilité **CTFd 3.3.0**.
Notre cible est **CTFd 3.8.6**. `THEME_FALLBACK` (défaut `true` depuis CTFd 3.4)
complète les templates manquants avec le thème `core`.
Tester l’UI après activation ; si cassé, revenir au thème `core`.

### Re-vendoring

```bash
python3 scripts/main.py vendor-theme
```
