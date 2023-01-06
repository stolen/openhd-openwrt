#include "camera_discovery.h"

#include <fcntl.h>
#include <libv4l2.h>
#include <linux/videodev2.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <iostream>
#include <regex>

#include "camera.hpp"
#include "camera_discovery_helper.hpp"
#include "libcamera_detect.hpp"
#include "openhd-util-filesystem.hpp"
#include "openhd-util.hpp"


DCameras::DCameras(const OHDPlatform ohdPlatform) :
	m_platform(ohdPlatform){
  m_console=openhd::log::create_or_get("v_dcameras");
  assert(m_console);
  m_enable_debug=OHDUtil::get_ohd_env_variable_bool("OHD_DISCOVER_CAMERAS_DEBUG");
  // always enabled for now
  // TODO fixme
  if(m_enable_debug){
    m_console->set_level(spd::level::debug);
    m_console->debug("m_enable_debug=true");
  }
}

DiscoveredCameraList DCameras::discover_internal() {
  m_console->debug("discover_internal()");
  // Only on raspberry pi with the old broadcom stack we need a special detection method for the rpi CSI camera.
  // On all other platforms (for example jetson) the CSI camera is exposed as a normal V4l2 linux device,and we cah
  // check the driver if it is actually a CSI camera handled by nvidia.
  // Note: With libcamera, also the rpi will do v4l2 for cameras.
  if(m_platform.platform_type==PlatformType::RaspberryPi){
    detect_raspberrypi_broadcom_csi();
    if(!detect_rapsberrypi_veye_v4l2_aaargh()){
      m_console->warn("Skipping libcamera detect, since it might pick up a veye cam by accident even though it cannot do it");
      detect_raspberry_libcamera();
    }
  }
  else if(m_platform.platform_type == PlatformType::Allwinner){
    detect_allwinner_csi();
  }
  // Allwinner 3.4 kernel v4l2 implementation is so sketchy that probing it can stop it working.
  if(m_platform.platform_type != PlatformType::Allwinner){
    // I think these need to be run before the detectv4l2 ones, since they are then picked up just like a normal v4l2 camera ??!!
    // Will need custom debugging before anything here is usable again though.
    DThermalCamerasHelper::enableFlirIfFound();
    DThermalCamerasHelper::enableSeekIfFound();
    // This will detect all cameras (CSI or not) that do it the proper way (linux v4l2)
    detect_v4l2();
  }
  argh_cleanup();
  // write to json for debugging
  write_camera_manifest(m_cameras);
  return m_cameras;
}

void DCameras::detect_raspberrypi_broadcom_csi() {
  m_console->debug("detect_raspberrypi_broadcom_csi()");
  const auto vcgencmd_result=OHDUtil::run_command_out("vcgencmd get_camera");
  if(vcgencmd_result==std::nullopt){
    m_console->debug("detect_raspberrypi_broadcom_csi() vcgencmd not found");
    return;
  }
  const auto& raw_value=vcgencmd_result.value();
  std::smatch result;
  // example "supported=2 detected=2"
  const std::regex r{R"(supported=([\d]+)\s+detected=([\d]+))"};
  if (!std::regex_search(raw_value, result, r)) {
    m_console->debug("detect_raspberrypi_broadcom_csi() no regex match");
    return;
  }
  if (result.size() != 3) {
    m_console->debug("detect_raspberrypi_broadcom_csi() regex unexpected result");
    return;
  }
  const std::string supported = result[1];
  const std::string detected = result[2];
  m_console->debug("detect_raspberrypi_broadcom_csi() supported={} detected={}",supported,detected);
  const auto camera_count = atoi(detected.c_str());
  if (camera_count >= 1) {
    Camera camera;
    camera.name = "Pi_CSI_0";
    camera.vendor = "RaspberryPi";
    camera.type = CameraType::RPI_CSI_MMAL;
    camera.bus = "0";
    camera.index = m_discover_index;
    m_discover_index++;
    CameraEndpoint endpoint=DRPICamerasHelper::createCameraEndpointRpi(false);
    m_camera_endpoints.push_back(endpoint);
    m_cameras.push_back(camera);
  }
  if (camera_count >= 2) {
    Camera camera;
    camera.name = "Pi_CSI_1";
    camera.vendor = "RaspberryPi";
    camera.type = CameraType::RPI_CSI_MMAL;
    camera.bus = "1";
    camera.index = m_discover_index;
    m_discover_index++;
    CameraEndpoint endpoint=DRPICamerasHelper::createCameraEndpointRpi(true);
    m_camera_endpoints.push_back(endpoint);
    m_cameras.push_back(camera);
  }
}
void DCameras::detect_allwinner_csi() {
  m_console->debug("detect_allwinner_csi(");
  
  if(OHDFilesystemUtil::exists("/dev/video0")){
    m_console->debug("Camera set as Allwinner_CSI_0");
    Camera camera;
    camera.name = "Allwinner_CSI_0";
    camera.vendor = "Allwinner";
    camera.type = CameraType::ALLWINNER_CSI;
    camera.bus = "0";
    camera.index = m_discover_index;
    m_discover_index++;
    CameraEndpoint endpoint=DRPICamerasHelper::createCameraEndpointAllwinner();
    m_camera_endpoints.push_back(endpoint);
    m_cameras.push_back(camera);
  }
}

bool DCameras::detect_rapsberrypi_veye_v4l2_aaargh() {
  const auto v4l2_info_video0_opt=OHDUtil::run_command_out("v4l2-ctl --info --device /dev/video0");
  if(!v4l2_info_video0_opt.has_value()){
    m_console->warn("Veye detetct unexpected result, autodetect doesnt work");
    return false;
  }
  const auto& v4l2_info_video0=v4l2_info_video0_opt.value();
  bool has_veye=OHDUtil::contains(v4l2_info_video0,"veye327") || OHDUtil::contains(v4l2_info_video0,"csimx307");
  if(OHDFilesystemUtil::exists("/boot/tmp_force_veye.txt")){
    m_console->warn("Forcing veye");
    has_veye= true;
  }
  if(!has_veye){
    return false;
  }
  m_console->info("Detected veye CSI camera");
  Camera camera;
  camera.type=CameraType::RPI_VEYE_CSI_V4l2;
  camera.bus="0";
  camera.index=0;
  camera.name = "Pi_VEYE_0";
  camera.vendor = "VEYE";
  m_cameras.push_back(camera);
  return true;
}

#ifdef OPENHD_LIBCAMERA_PRESENT
void DCameras::detect_raspberry_libcamera() {
  m_console->debug("detect_raspberry_libcamera()");
  auto cameras = openhd::libcameradetect::get_csi_cameras();
  m_console->debug("Libcamera:discovered {} cameras",cameras.size());
  for (const auto& camera : cameras) {
    // TODO: filter out other cameras
    m_cameras.push_back(camera);
  }
}
#else
void DCameras::detect_raspberry_libcamera() {
  m_console->warn("detect_raspberry_libcamera - built without libcamera, libcamera features unavailable");
}
#endif

void DCameras::detect_v4l2() {
  m_console->debug("detect_v4l2()");
  // Get all the devices to take into consideration.
  const auto devices = DV4l2DevicesHelper::findV4l2VideoDevices();
  for (const auto &device: devices) {
    probe_v4l2_device(device);
  }
}

void DCameras::probe_v4l2_device(const std::string &device) {
  m_console->trace("probe_v4l2_device() {}",device);
  std::stringstream command;
  command << "udevadm info ";
  command << device.c_str();
  const auto udev_info_opt=OHDUtil::run_command_out(command.str().c_str());
  if(udev_info_opt==std::nullopt){
    m_console->debug("udev_info no result");
    return;
  }
  const auto& udev_info=udev_info_opt.value();
  Camera camera;
  // check for device name
  std::smatch model_result;
  const std::regex model_regex{"ID_MODEL=([\\w]+)"};
  if (std::regex_search(udev_info, model_result, model_regex)) {
    if (model_result.size() == 2) {
      camera.name = model_result[1];
    }
  }
  // check for device vendor
  std::smatch vendor_result;
  const std::regex vendor_regex{"ID_VENDOR=([\\w]+)"};
  if (std::regex_search(udev_info, vendor_result, vendor_regex)) {
    if (vendor_result.size() == 2) {
      camera.vendor = vendor_result[1];
    }
  }
  // check for vid
  std::smatch vid_result;
  const std::regex vid_regex{"ID_VENDOR_ID=([\\w]+)"};
  if (std::regex_search(udev_info, vid_result, vid_regex)) {
    if (vid_result.size() == 2) {
      camera.vid = vid_result[1];
    }
  }
  // check for pid
  std::smatch pid_result;
  const std::regex pid_regex{"ID_MODEL_ID=([\\w]+)"};
  if (std::regex_search(udev_info, pid_result, pid_regex)) {
    if (pid_result.size() == 2) {
      camera.pid = pid_result[1];
    }
  }
  CameraEndpoint endpoint;
  endpoint.device_node = device;
  if (!process_v4l2_node(device, camera, endpoint)) {
    return;
  }
  bool found = false;
  for (auto &stored_camera: m_cameras) {
    if (stored_camera.bus == camera.bus) {
      found = true;
    }
  }
  if (!found) {
    camera.index = m_discover_index;
    m_discover_index++;
    m_cameras.push_back(camera);
  }
  m_camera_endpoints.push_back(endpoint);
}

// Util so we can't forget to clse the fd
class V4l2FPHolder{
 public:
  V4l2FPHolder(const std::string &node,const PlatformType& platform_type){
    // fucking hell, on jetson v4l2_open seems to be bugged
    // https://forums.developer.nvidia.com/t/v4l2-open-create-core-with-jetpack-4-5-or-later/170624/6
    if(platform_type==PlatformType::Jetson){
      fd = open(node.c_str(), O_RDWR | O_NONBLOCK, 0);
    }else{
      fd = v4l2_open(node.c_str(), O_RDWR);
    }
  }
  ~V4l2FPHolder(){
    if(fd!=-1){
      v4l2_close(fd);
    }
  }
  [[nodiscard]] bool opened_successfully() const{
    return fd!=-1;
  }
  int fd;
};

bool DCameras::process_v4l2_node(const std::string &node, Camera &camera, CameraEndpoint &endpoint) {
  m_console->trace( "process_v4l2_node ({})",node);

  auto v4l2_fp_holder=std::make_unique<V4l2FPHolder>(node,m_platform.platform_type);
  if(!v4l2_fp_holder->opened_successfully()){
    m_console->debug("Can't open: "+node);
    return false;
  }
  struct v4l2_capability caps = {};
  if (ioctl(v4l2_fp_holder->fd, VIDIOC_QUERYCAP, &caps) == -1) {
    m_console->debug("Capability query failed: "+node);
    return false;
  }
  const std::string driver((char *)caps.driver);
  m_console->trace("Driver is:"+driver);
  if (driver == "uvcvideo") {
    camera.type = CameraType::UVC;
    m_console->debug("Found UVC camera");
  } else if (driver == "tegra-video") {
    camera.type = CameraType::JETSON_CSI;
    m_console->debug("Found Jetson CSI camera");
  } else if (driver == "rk_hdmirx") {
    camera.type = CameraType::ROCKCHIP_HDMI;
    m_console->debug("Found Rockchip HDMI input");
  } else if (driver == "v4l2 loopback") {
    // this is temporary, we are not going to use v4l2loopback for thermal cameras they'll be directly
    // handled by the camera service instead work anyways
    // Consti10: Removed for this release, won't
    //camera.type = CameraTypeV4L2Loopback;
    m_console->debug("Found v4l2 loopback camera (likely a thermal camera), TODO implement me");
    return false;
  } else {
    // While for example newer libcamera uses the v4l2 stack, using v4l2 for those cameras is a bad idea - they
    // have a custom cam type and custom specific pipelines
    if(driver=="unicam" || driver=="bcm2835-isp"){
      // handled by specialized code (camera not of type v4l2)
      return false;
    }else if(driver=="bcm2835-codec"){
      // rpi encoder
      return false;
    }else if(driver=="rpivid"){
      // rpi decoder
      return false;
    }
    m_console->debug("Found V4l2 device with unknown driver: [{}]",driver);
    return false;
  }
  const std::string bus((char *)caps.bus_info);
  camera.bus = bus;
  endpoint.bus = bus;
  if (!(caps.capabilities & V4L2_BUF_TYPE_VIDEO_CAPTURE) && driver != "rk_hdmirx") {
    m_console->debug("Not a capture device: "+node);
    return false;
  }
  struct v4l2_fmtdesc fmtdesc{};
  memset(&fmtdesc, 0, sizeof(fmtdesc));
  fmtdesc.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  while (ioctl(v4l2_fp_holder->fd, VIDIOC_ENUM_FMT, &fmtdesc) == 0) {
    struct v4l2_frmsizeenum frmsize{};
    frmsize.pixel_format = fmtdesc.pixelformat;
    frmsize.index = 0;
    while (ioctl(v4l2_fp_holder->fd, VIDIOC_ENUM_FRAMESIZES, &frmsize) == 0) {
      struct v4l2_frmivalenum frmival{};
      if (frmsize.type == V4L2_FRMSIZE_TYPE_DISCRETE) {
        frmival.index = 0;
        frmival.pixel_format = fmtdesc.pixelformat;
        frmival.width = frmsize.discrete.width;
        frmival.height = frmsize.discrete.height;

        while (ioctl(v4l2_fp_holder->fd, VIDIOC_ENUM_FRAMEINTERVALS, &frmival) == 0) {
          if (frmival.type == V4L2_FRMIVAL_TYPE_DISCRETE) {
            std::stringstream new_format;
            if (fmtdesc.pixelformat == V4L2_PIX_FMT_H264) {
              endpoint.support_h264 = true;
            }
#if defined V4L2_PIX_FMT_H265
            else if (fmtdesc.pixelformat == V4L2_PIX_FMT_H265) {
              endpoint.support_h265 = true;
            }
#endif
            else if (fmtdesc.pixelformat == V4L2_PIX_FMT_MJPEG) {
              endpoint.support_mjpeg = true;
            } else {
              // if it supports something else it's one of the raw formats, the camera service will
              // figure out what to do with it
              endpoint.support_raw = true;
            }
            new_format << fmtdesc.description;
            new_format << "|";
            new_format << frmsize.discrete.width;
            new_format << "x";
            new_format << frmsize.discrete.height;
            new_format << "@";
            new_format << frmival.discrete.denominator;
            endpoint.formats.push_back(new_format.str());
            m_console->debug( "Found format: "+new_format.str());
          }
          frmival.index++;
        }
      }
      frmsize.index++;
    }
    fmtdesc.index++;
  }
  m_console->debug("process_v4l2_node done");
  return true;
}

void DCameras::argh_cleanup() {
  // Fixup endpoints, would be better to seperate the discovery steps properly so that this is not needed
  for (auto &camera: m_cameras) {
    std::vector<CameraEndpoint> endpointsForThisCamera;
    for (const auto &endpoint: m_camera_endpoints) {
      if (camera.bus == endpoint.bus) {
        // an endpoint who cannot do anything is just a waste and added complexity for later modules
        if (endpoint.formats.empty()) {
          // not really an error, since it is an implementation issue during detection that is negated here
          m_console->debug("Discarding endpoint"+endpoint.device_node+" due to no formats");
          continue;
        }
        if (!endpoint.supports_anything()) {
          // not really an error, since it is an implementation issue during detection that is negated here
          m_console->debug("Discarding endpoint "+endpoint.device_node+" due to no capabilities");
          continue;
        }
        endpointsForThisCamera.push_back(endpoint);
      }
    }
    camera.endpoints = endpointsForThisCamera;
    // also, a camera without a endpoint - what the heck should that be
    if (camera.endpoints.empty()) {
      m_console->warn("Warning Camera without endpoints");
    }
  }
  // make sure the camera indices are right
  int camIdx = 0;
  for (auto &camera: m_cameras) {
    camera.index = camIdx;
    camIdx++;
  }
  write_camera_manifest(m_cameras);
}

DiscoveredCameraList DCameras::discover(const OHDPlatform ohdPlatform) {
  auto discover=DCameras{ohdPlatform};
  return discover.discover_internal();
}
