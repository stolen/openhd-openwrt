#ifndef CAMERA_H
#define CAMERA_H

#include <array>
#include <chrono>
#include <vector>

#include "camera_holder.hpp"
#include "openhd-platform.hpp"

#include "openhd-spdlog.hpp"

/**
 * Discover all connected cameras and for some camera(s) (E.g. USB cameras and/or cameras that use v4l2)
 * Figure out their capabilities via V4l2. Written as a class r.n but actually should only be a namespace.
 * The interesting bit is just the discover() method below.
 */
class DCameras {
 public:
  explicit DCameras(OHDPlatform ohdPlatform);
  virtual ~DCameras() = default;
  /**
   * Discover all cameras connected to this system.
   * @returns A list of detected cameras, or an empty vector if no cameras have been found.
   * Note that at this point, we haven't performed the settings lookup for the Camera(s) - this just exposes the available cameras
   * and their capabilities.
   * @param ohdPlatform the platform we are running on, detection depends on the platform type.
   */
  static std::vector<Camera> discover(OHDPlatform ohdPlatform);
 private:
  DiscoveredCameraList discover_internal();
  void argh_cleanup();
 private:
  /*
   * These are for platform-specific camera access methods, most can also be
   * accessed through v4l2 but there are sometimes downsides to doing that. For
   * example on the Pi, v4l2 can have higher latency than going through the
   * broadcom API, and at preset bcm2835-v4l2 doesn't support all of the ISP
   * controls.
   *
   */
  /**
   * This is used when the gpu firmware is in charge of the camera, we have to
   * ask it.
   */
  void detect_raspberrypi_broadcom_csi();
  // hacky
  bool detect_rapsberrypi_veye_v4l2_aaargh();

  /*
   * Detecting via libcamera.
   * Actually all cameras in system available via libcamera.
   * Moreover libcamera cameras is v4l devices and can be used as usual.
   * But here we are using libcamera only for undetected cameras for compatability
   */
  void detect_raspberry_libcamera();

  /*
   * Detect all v4l2 cameras, that is cameras that show up as a v4l2 device
   * (/dev/videoXX)
   */
  void detect_v4l2();

  /* Detect allwinner camera. Uses v4l2, but needs a few tweaks */
  void detect_allwinner_csi();
  
  /**
   * Something something stephen.
   */
  void probe_v4l2_device(const std::string &device_node);
  /**
   * Something something stephen.
   */
  bool process_v4l2_node(const std::string &node, Camera &camera,
                         CameraEndpoint &endpoint);

  // NOTE: IP cameras cannot be auto detected !

  std::vector<Camera> m_cameras;
  std::vector<CameraEndpoint> m_camera_endpoints;

  int m_discover_index = 0;

  const OHDPlatform m_platform;
  bool m_enable_debug;

 private:
  std::shared_ptr<spdlog::logger> m_console;
};

#endif
