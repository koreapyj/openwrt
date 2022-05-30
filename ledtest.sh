#!/bin/sh

for port in `echo -e "0\n8\n16\n20\n24\n25\n26\n27"`; do
    en_ctrl="/sys/kernel/debug/rtl838x/led/led_port_sw_en_ctrl_`echo $(($port >> 3))`"
    ctrl="/sys/kernel/debug/rtl838x/led/led_port_sw_ctrl_`printf %02d $port`"

    ctrl_val=`cat $en_ctrl`
    ctrl_val_en=$(($ctrl_val | (0xf << 4*($port%8))))
    ctrl_val_dis=$(($ctrl_val & ~(0xf << 4*($port%8))))

    echo "Port $port (`basename $en_ctrl`)"
    echo "  en_ctrl `cat $en_ctrl` -> 0x`printf %x $ctrl_val_en`"
    echo $ctrl_val_en > $en_ctrl

    for led in $(seq 0 3); do
        val=$((0x7 << ($led*3)))
        echo "  SW_COPR_LED$led""_MODE on (0x`printf %x $val`)"
        echo "0x`printf %x $val`" > $ctrl
        echo 0x1 > /sys/kernel/debug/rtl838x/led/sw_led_load
        sleep 1
    done

    for led in $(seq 0 3); do
        val=$((0x7 << (($led+4)*3)))
        echo "  SW_FIB_LED$led""_MODE on (0x`printf %x $val`)"
        echo "0x`printf %x $val`" > $ctrl
        echo 0x1 > /sys/kernel/debug/rtl838x/led/sw_led_load
        sleep 1
    done

    echo 0x0 > $ctrl
    echo 0x1 > /sys/kernel/debug/rtl838x/led/sw_led_load
    echo $ctrl_val_dis > $en_ctrl
done
