# Image officielle (Vector, ClickHouse, Redis, PostgreSQL, Trivy) + correctifs Alpine publiés depuis sa
# construction : les éditeurs ne reconstruisent leurs images qu'aux nouvelles versions, alors qu'un correctif
# d'OpenSSL, de zlib… arrive entre-temps dans les dépôts Alpine (relevé par Cyberwatch sur la VM). Reconstruite à
# chaque mise à jour.
ARG BASE
FROM ${BASE}
# gosu (PostgreSQL) : compilé avec une ancienne version de Go (des dizaines de CVE). Supprimé (un fichier seulement
# recouvert resterait dans la couche d'origine, et les analyseurs comme Trivy le signaleraient encore) et remplacé
# dans le script d'entrée par su-exec, son équivalent en C fourni par Alpine (même syntaxe : <compte> <commande>).
# Si une version du script d'entrée appelle gosu autrement, la construction échoue : à adapter ici.
RUN apk upgrade --no-cache \
 && if [ -e /usr/local/bin/gosu ]; then \
      apk add --no-cache su-exec && rm /usr/local/bin/gosu \
      && sed -i 's/exec gosu /exec su-exec /' /usr/local/bin/docker-entrypoint.sh \
      && grep -q 'exec su-exec ' /usr/local/bin/docker-entrypoint.sh \
      && ! grep -q 'gosu ' /usr/local/bin/docker-entrypoint.sh; \
    fi
