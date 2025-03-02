#!/bin/bash

LOG_FILE="script.log"
USERS_FILE="users.md"

log() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

if [[ ! -f "$USERS_FILE" ]]; then
    log "Erreur : Le fichier $USERS_FILE n'existe pas."
    exit 1
fi

log "Début de la gestion des utilisateurs."

grep -A1000 "\| Name   " "$USERS_FILE" | tail -n +3 | while IFS='|' read -r _ NAME PRIMARY_GROUP OTHER_GROUPS _; do
    NAME=$(echo "$NAME" | xargs)
    PRIMARY_GROUP=$(echo "$PRIMARY_GROUP" | xargs)
    OTHER_GROUPS=$(echo "$OTHER_GROUPS" | xargs | tr ',' ' ')

    if [[ -z "$NAME" || "$NAME" == "Name" ]]; then
        continue
    fi

    log "Création de l'utilisateur : $NAME"

    if ! getent group "$PRIMARY_GROUP" >/dev/null; then
        groupadd "$PRIMARY_GROUP"
        log "Groupe principal créé : $PRIMARY_GROUP"
    fi

    PASSWORD=$(openssl rand -base64 12)
    useradd -m -s /bin/bash -g "$PRIMARY_GROUP" "$NAME"
    echo "$NAME:$PASSWORD" | chpasswd
    log "Utilisateur $NAME créé avec le groupe principal $PRIMARY_GROUP"

    if [[ "$OTHER_GROUPS" != "(aucun)" && -n "$OTHER_GROUPS" ]]; then
        for GROUP in $OTHER_GROUPS; do
            if ! getent group "$GROUP" >/dev/null; then
                groupadd "$GROUP"
                log "Groupe secondaire créé : $GROUP"
            fi
        done

        usermod -aG $(echo "$OTHER_GROUPS" | tr ' ' ',') "$NAME"
        log "Ajout de $NAME aux groupes secondaires : $OTHER_GROUPS"
    else
        log "Pas de groupes secondaires pour $NAME."
    fi

done

log "Gestion des utilisateurs terminée."