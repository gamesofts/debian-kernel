apt-get --fix-broken install -y && apt-get autoremove -y
rm -rf bbr
mkdir bbr && cd bbr

github_tag=$(curl -s 'https://api.github.com/repos/gamesofts/debian-kernel/releases' | grep 'Debian_Kernel' | grep '_bbrplus_' | head -n 1 | awk -F '"' '{print $4}' | awk -F '[/]' '{print $8}')
github_ver=$(curl -s 'https://api.github.com/repos/gamesofts/debian-kernel/releases' | grep ${github_tag} | grep 'deb' | grep 'headers' | awk -F '"' '{print $4}' | awk -F '[/]' '{print $9}' | awk -F '[-]' '{print $3}' | awk -F '[_]' '{print $1}')

if [[ -z $github_ver ]]; then
  echo "未获取到可用内核版本，退出！"
  exit 1
fi

echo -e "开始安装内核: ${Green_font_prefix}${github_ver}${Font_color_suffix}"
kernel_version=$github_ver

deb_total=$(dpkg -l | grep linux-headers | awk '{print $2}' | grep -v "${kernel_version}" | wc -l)
if [ "${deb_total}" ] >"1"; then
  for ((integer = 1; integer <= ${deb_total}; integer++)); do
  deb_del=$(dpkg -l | grep linux-headers | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer})
  apt-get purge -y ${deb_del}
  apt-get autoremove -y
  done
fi

headurl=$(curl -s 'https://api.github.com/repos/gamesofts/debian-kernel/releases' | grep ${github_tag} | grep 'deb' | grep 'headers' | awk -F '"' '{print $4}')
imgurl=$(curl -s 'https://api.github.com/repos/gamesofts/debian-kernel/releases' | grep ${github_tag} | grep 'deb' | grep 'image' | grep -v 'dev\|dbg' | awk -F '"' '{print $4}')

wget "$headurl" -O "linux-headers-d10.deb"
wget "$imgurl" -O "linux-image-d10.deb"

dpkg -i linux-image-d10.deb
dpkg -i linux-headers-d10.deb

cd .. && rm -rf bbr
deb_total=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l)
if [ "${deb_total}" ] >"1"; then
  for ((integer = 1; integer <= ${deb_total}; integer++)); do
  deb_del=$(dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer})
  apt-get purge -y ${deb_del}
  apt-get autoremove -y
  done
fi

if _exists "update-grub"; then
  update-grub
elif [ -f "/usr/sbin/update-grub" ]; then
  /usr/sbin/update-grub
else
  apt install grub2-common -y
  update-grub
fi

if [[ -z "$(find /boot -type f -name 'vmlinuz-*' ! -name 'vmlinuz-*rescue*')" ]]; then
  echo -e "\033[0;31m警告: 未发现内核文件，请勿重启系统，不卸载内核版本选择30安装默认内核救急！\033[0m"
else
  echo -e "\033[0;32m发现内核文件，看起来可以重启。\033[0m"
fi
