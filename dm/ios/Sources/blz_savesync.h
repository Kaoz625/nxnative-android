// save_sync - one save shared by every device that plays this game (PS5, iPhone, Android), kept by the
// savesync store on the home server (Blazing tools/savesync, HTTP over Tailscale). Self-contained: plain
// sockets + its own SHA-256 + tar, no platform frameworks, so the same file works on iOS and Android.
//
// Start(): at launch, BEFORE the game reads its save: send the local save to the store; if the store has a
// newer one, keep a local backup and put the newer one in place. Then a background thread sends every new
// local save (checks every few seconds, waits until the files stop changing). The game never gets its save
// replaced while it runs: a newer save found mid-game is applied at the next start.
// OnBackground(): called when the app goes to the background: sends a changed save right away.
// Everything is logged to <save root>/../savesync.log. Off when <Documents>/savesync.txt says "off".
#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace blz_savesync {

struct Config {
  std::string host = "100.104.191.30";  // mac1 on the tailnet
  int port = 4481;
  std::string game = "dante-inferno";
  std::string device = "iphone-15pm";
  std::filesystem::path root;  // folder that holds the synced sub-folders
  std::vector<std::string> include = {"B13EBABEBABEBABE/", "achievements/"};
  int poll_seconds = 5;
};

void Start(Config config);
void OnBackground();

// Exposed for the host test (tests/save_sync_test.cpp).
std::string Sha256Hex(const std::string& data);

}  // namespace blz_savesync
