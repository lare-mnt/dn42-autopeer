#!/bin/bash
ACTION=$1

case $ACTION in
        enable)
                systemctl enable "wg-quick@dn42_$2";
                ;;

        disable)
                systemctl disable "wg-quick@dn42_$2"
                ;;

        start)
                systemctl start "wg-quick@dn42_$2"
                ;;

        stop)
                systemctl stop "wg-quick@dn42_$2"
                ;;

        *)
                echo “User Selected Choice not present”
                exit 1

esac