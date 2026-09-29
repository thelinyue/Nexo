import { Icon } from "@iconify/react/offline";
import type { IconifyIcon, IconProps as IconifyProps } from "@iconify/react/offline";
import arrowDownLeftIcon from "@iconify-icons/tabler/arrow-down-left";
import arrowLeftIcon from "@iconify-icons/tabler/arrow-left";
import arrowUpRightIcon from "@iconify-icons/tabler/arrow-up-right";
import checkIcon from "@iconify-icons/tabler/check";
import chevronDownIcon from "@iconify-icons/tabler/chevron-down";
import chevronRightIcon from "@iconify-icons/tabler/chevron-right";
import circleAlertIcon from "@iconify-icons/tabler/alert-circle";
import circleCheckIcon from "@iconify-icons/tabler/circle-check";
import circleHelpIcon from "@iconify-icons/tabler/help-circle";
import clockIcon from "@iconify-icons/tabler/clock";
import copyIcon from "@iconify-icons/tabler/copy";
import ellipsisIcon from "@iconify-icons/tabler/dots";
import eyeIcon from "@iconify-icons/tabler/eye";
import eyeOffIcon from "@iconify-icons/tabler/eye-off";
import globeIcon from "@iconify-icons/tabler/world";
import houseIcon from "@iconify-icons/tabler/home";
import keyRoundIcon from "@iconify-icons/tabler/key";
import logOutIcon from "@iconify-icons/tabler/logout";
import networkIcon from "@iconify-icons/tabler/network";
import pauseIcon from "@iconify-icons/tabler/player-pause";
import plusIcon from "@iconify-icons/tabler/plus";
import powerIcon from "@iconify-icons/tabler/power";
import powerOffIcon from "@iconify-icons/tabler/plug-off";
import refreshCwIcon from "@iconify-icons/tabler/refresh";
import rotateCcwIcon from "@iconify-icons/tabler/restore";
import searchIcon from "@iconify-icons/tabler/search";
import serverIcon from "@iconify-icons/tabler/server";
import settingsIcon from "@iconify-icons/tabler/settings";
import shieldCheckIcon from "@iconify-icons/tabler/shield-check";
import trash2Icon from "@iconify-icons/tabler/trash";
import triangleAlertIcon from "@iconify-icons/tabler/alert-triangle";
import userRoundIcon from "@iconify-icons/tabler/user";
import usersIcon from "@iconify-icons/tabler/users";
import xIcon from "@iconify-icons/tabler/x";

type IconProps = Omit<IconifyProps, "icon" | "width" | "height" | "strokeWidth"> & { size?: number | string };

/** 统一使用本地 Tabler 线性图标，首屏和离线场景均无需请求图标服务。
 * 保留调用处的尺寸与 SVG 属性；图标默认仅作装饰，可访问名称由所属按钮或文字提供。
 * 直接输出 SVG，不增加容器，避免改变导航、按钮及状态角标的布局。
 */
function createIcon(data: IconifyIcon) {
  return function AppIcon({ size = 24, ...props }: IconProps) {
    return <Icon icon={data} width={size} height={size} aria-hidden="true" focusable="false" {...props} />;
  };
}

export const ArrowDownLeft = createIcon(arrowDownLeftIcon);
export const ArrowLeft = createIcon(arrowLeftIcon);
export const ArrowUpRight = createIcon(arrowUpRightIcon);
export const Check = createIcon(checkIcon);
export const ChevronDown = createIcon(chevronDownIcon);
export const ChevronRight = createIcon(chevronRightIcon);
export const CircleAlert = createIcon(circleAlertIcon);
export const CircleCheck = createIcon(circleCheckIcon);
export const CircleHelp = createIcon(circleHelpIcon);
export const Clock = createIcon(clockIcon);
export const Copy = createIcon(copyIcon);
export const Ellipsis = createIcon(ellipsisIcon);
export const Eye = createIcon(eyeIcon);
export const EyeOff = createIcon(eyeOffIcon);
export const Globe = createIcon(globeIcon);
export const House = createIcon(houseIcon);
export const KeyRound = createIcon(keyRoundIcon);
export const LogOut = createIcon(logOutIcon);
export const Network = createIcon(networkIcon);
export const Pause = createIcon(pauseIcon);
export const Plus = createIcon(plusIcon);
export const Power = createIcon(powerIcon);
export const PowerOff = createIcon(powerOffIcon);
export const RefreshCw = createIcon(refreshCwIcon);
export const RotateCcw = createIcon(rotateCcwIcon);
export const Search = createIcon(searchIcon);
export const Server = createIcon(serverIcon);
export const Settings = createIcon(settingsIcon);
export const ShieldCheck = createIcon(shieldCheckIcon);
export const Trash2 = createIcon(trash2Icon);
export const TriangleAlert = createIcon(triangleAlertIcon);
export const UserRound = createIcon(userRoundIcon);
export const Users = createIcon(usersIcon);
export const X = createIcon(xIcon);
export const Globe2 = Globe;
