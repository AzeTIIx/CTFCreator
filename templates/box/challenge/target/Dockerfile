# Cible minimale (template) : serveur SSH + un flag user + un flag root +
# une élévation d'exemple (sudo find, GTFOBins). À PERSONNALISER pour ton
# scénario. Root assumé (sshd port 22) — cohérent avec le lab local.
FROM debian:12-slim

ARG FLAG_USER=AFLO{local_test_only}
ARG FLAG_ROOT=AFLO{local_test_only}

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server sudo \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd

# Compte étudiant. TODO: remplace le mot de passe / passe en clé selon ton
# scénario de foothold. Ici mot de passe pour que la box démarre et se teste.
RUN useradd --create-home --shell /bin/bash user \
    && echo 'user:changeme' | chpasswd

# Flag "user" (preuve d'accès) dans le home ; flag "root" dans /root.
RUN printf '%s\n' "$FLAG_USER" > /home/user/user.txt \
    && chown user:user /home/user/user.txt && chmod 600 /home/user/user.txt \
    && printf '%s\n' "$FLAG_ROOT" > /root/root.txt && chmod 600 /root/root.txt

# Élévation d'exemple (à remplacer par TA faiblesse pédagogique) :
RUN echo 'user ALL=(root) NOPASSWD: /usr/bin/find' > /etc/sudoers.d/user-find \
    && chmod 440 /etc/sudoers.d/user-find

# TODO: durcis via un sshd_config dédié (clé, AllowUsers, etc.).
USER root
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
