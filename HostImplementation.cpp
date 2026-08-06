/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright (c) 2025 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "HostImplementation.h"
#include <fstream>

using namespace widevine;
using namespace WPEFramework;

namespace CDMi {

HostImplementation::HostImplementation() 
  : widevine::Cdm::IStorage()
  , widevine::Cdm::IClock()
  , widevine::Cdm::ITimer()
#if (WIDEVINE_VERSION == 18)
  , widevine::Cdm::ILogger()
#endif
  , _timer(Core::Thread::DefaultStackSize(),  _T("widevine"))
  , _basepath("")
  , _cache() {
}

HostImplementation::~HostImplementation() {
}

void HostImplementation::SetBasePath(const std::string& basepath) {
  TRACE_L1("basepath %s", basepath.c_str());
  _basepath = basepath;
}

void HostImplementation::PreloadFile(const std::string& filename, std::string&& filecontent ) {
  _cache.emplace(filename, filecontent);
}

bool HostImplementation::readFromeFile(const std::string& name, std::string* data) {
  struct stat Stat;
  string filePath(_basepath + '/' + name);
  if (stat(filePath.c_str(), &Stat) < 0)
    return false;
  
  std::ifstream File(filePath, std::ios::binary | std::ios::in);
  data->resize(Stat.st_size);
  File.read(&(*data)[0], data->size());
  return true;
}

bool HostImplementation::writeToFile(const std::string& name, const std::string& data) {
  string filePath(_basepath + '/' + name);
  try
  {
    std::ofstream File(filePath, std::ios::binary | std::ios::out);
    File.write(data.data(), data.size());
    return true;
  }
  catch (...)
  {
    return false;
  }
}

// widevine::Cdm::IStorage implementation
// ---------------------------------------------------------------------------
/* virtual */ bool HostImplementation::read(const std::string& name, std::string* data) {
  StorageMap::iterator it = _cache.find(name);
  bool ok = it != _cache.end();
  TRACE_L1("read: %s: cache %s", name.c_str(), ok ? "ok" : "fail");
  if (ok) {
    TRACE_L1("name %s read from cache", name.c_str());
    *data = it->second;
    return true;
  }

  TRACE_L1("name %s read from file", name.c_str());
  if(readFromeFile(name, data))
  {
      TRACE_L1("name %s read and update cache %zu", name.c_str(), data->size());
      _cache.emplace(name, std::string(reinterpret_cast<const char*>(data->data()), data->size()));
      return true;
  } else {
      TRACE_L1("name %s not found!", name.c_str());
      return false;
  }
}

/* virtual */ bool HostImplementation::write(const std::string& name, const std::string& data) {
  TRACE_L1("write: %s", name.c_str());
  _cache[name] = data;
  if(writeToFile(name, data)) {
      TRACE_L1("success to write back %s.", name.c_str());
      return true;
  } else {
      TRACE_L1("fail to write back %s!", name.c_str());
      return false;
  }
}

/* virtual */ bool HostImplementation::exists(const std::string& name) {
  StorageMap::iterator it = _cache.find(name);
  bool ok = it != _cache.end();
  TRACE_L1("exists? %s: %s", name.c_str(), ok ? "true" : "false");
  if(ok) {
    TRACE_L1("name %s cache hit", name.c_str());
    return true;
  }

  string filePath(_basepath + '/' + name);
  ok = access(filePath.c_str(), F_OK) == 0;
  TRACE_L1("name %s cache miss, check file at %s, ok %d", name.c_str(), filePath.c_str(), ok);
  return ok;
}

/* virtual */ bool HostImplementation::remove(const std::string& name) {
  TRACE_L1("remove: %s", name.c_str());
  if (name.empty()) {
    // If no name, delete all files (see DeviceFiles::DeleteAllFiles())
    TRACE_L1("remove: all cache");
    _cache.clear();

    { // Remove all files under a base path
      DIR *Directory = opendir(_basepath.c_str());
      if (Directory == NULL)
        return false;

      struct dirent *Entry;
      while (Entry = readdir(Directory), Entry != NULL) {
        string filePath(_basepath + '/' + Entry->d_name);
        TRACE_L1("remove %s", filePath.c_str());
        unlink(filePath.c_str());
      }

      closedir(Directory);
    }
    return true;
  }
  
  // When name contains a wild card
  if (name.find("*") != string::npos) {
    TRACE_L1("remove %s with wildcard", name.c_str());
    DIR *Directory = opendir(_basepath.c_str());
    if (Directory == NULL)
      return false;

    struct dirent *Entry;
    while (Entry = readdir(Directory), Entry != NULL) {
      if (fnmatch(name.c_str(), Entry->d_name, 0) == 0) {
        StorageMap::iterator it = _cache.find(Entry->d_name);
        if(it != _cache.end()) {
          TRACE_L1("remove %s from cache", Entry->d_name);
          _cache.erase(Entry->d_name);
        }
        string filePath(_basepath + '/' + Entry->d_name);
        TRACE_L1("remove %s", filePath.c_str());
        unlink(filePath.c_str());
      }
    }

    closedir(Directory);
    return true;
  }

  // A specific name
  StorageMap::iterator it = _cache.find(name);
  if(it != _cache.end()) {
      TRACE_L1("remove %s from cache", name);
      _cache.erase(name);
  }

  string filePath(_basepath + '/' + name);
  TRACE_L1("remove %s", filePath.c_str());
  unlink(filePath.c_str());
  return true;
}

/* virtual */ int32_t HostImplementation::size(const std::string& name) {
  StorageMap::iterator it = _cache.find(name);
  if (it != _cache.end()) {
    TRACE_L1("name %s cache hit, size %d", name.c_str(), it->second.size());
    return it->second.size();
  }

  struct stat Stat;
  string filePath(_basepath + '/' + name);
  if (stat(filePath.c_str(), &Stat) < 0) {
    TRACE_L1("name %s not found", name.c_str());
    return -1;
  } else {
    TRACE_L1("name %s found, size %d", name.c_str(), Stat.st_size);
    return Stat.st_size;
  }
}

/* virtual */ bool HostImplementation::list(std::vector<std::string>* names) {
  DIR *Directory = opendir(_basepath.c_str());
  if (Directory == NULL)
    return false;

  names->clear();
  struct dirent *Entry;
  while (Entry = readdir(Directory), Entry != NULL) {
    TRACE_L1("name %s add to list", Entry->d_name);
    names->push_back(Entry->d_name);
  }

  closedir(Directory);
  return true;
}

// widevine::Cdm::IClock implementation
// ---------------------------------------------------------------------------
/* virtual */ int64_t HostImplementation::now() {
  return static_cast<int64_t>(Core::Time::Now().Ticks() / Core::Time::TicksPerMillisecond); // Ticks -> MilliSeconds
}

// widevine::Cdm::ITimer implementation
// ---------------------------------------------------------------------------
/* virtual */ void HostImplementation::setTimeout(int64_t delay_ms, IClient* client, void* context) {

  ASSERT ((delay_ms > 0) && (delay_ms < 0xFFFFFFFF));

  Core::Time timeOut = Core::Time::Now().Add(delay_ms);

  _timer.Schedule(timeOut.Ticks(), Timer(client, context));
}

/* virtual */ void HostImplementation::cancel(IClient* client) {
  _timer.Revoke(Timer(client, nullptr));
}

#if (WIDEVINE_VERSION == 18)
// widevine::Cdm::IClock implementation
// ---------------------------------------------------------------------------
/* virtual */ void HostImplementation::log(const std::string& message) {
  return;
}
#endif

} // namespace CDMi
