# ============================================================
# Makefile для криптографического приложения
# ============================================================

CXX        := g++
CXXFLAGS   := -std=c++17 -Wall -Wextra -O2 -Iinclude
LDFLAGS    := -ldl
SOFLAGS    := -shared -fPIC

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    LIB_EXT := so
endif
ifeq ($(UNAME_S),Darwin)
    LIB_EXT := dylib
    LDFLAGS :=
endif
ifeq ($(OS),Windows_NT)
    LIB_EXT := dll
    LDFLAGS :=
endif

SRC_DIR     := src
INC_DIR     := include
PLUGIN_DIR  := plugins
BUILD_DIR   := build
OBJ_DIR     := $(BUILD_DIR)/obj
BIN_DIR     := $(BUILD_DIR)
PLUGIN_OUT  := $(BUILD_DIR)/plugins

APP_SOURCES := $(wildcard $(SRC_DIR)/*.cpp)
APP_OBJECTS := $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(APP_SOURCES))
APP_TARGET  := $(BIN_DIR)/cryptoApp

PLUGIN_SOURCES := $(wildcard $(PLUGIN_DIR)/*.cpp)
PLUGIN_TARGETS := $(patsubst $(PLUGIN_DIR)/%.cpp, $(PLUGIN_OUT)/%.$(LIB_EXT), $(PLUGIN_SOURCES))

.PHONY: all clean run app plugins dirs help

all: dirs app plugins

dirs:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(PLUGIN_OUT)

app: $(APP_TARGET)

$(APP_TARGET): $(APP_OBJECTS)
	@echo "==> Линковка приложения: $@"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@echo "==> Компиляция: $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

plugins: $(PLUGIN_TARGETS)

$(PLUGIN_OUT)/%.$(LIB_EXT): $(PLUGIN_DIR)/%.cpp
	@echo "==> Сборка плагина: $@"
	$(CXX) $(CXXFLAGS) $(SOFLAGS) -o $@ $<

run: all
	@echo "==> Запуск приложения"
	@cd $(BIN_DIR) && ./cryptoApp

clean:
	@echo "==> Очистка"
	rm -rf $(BUILD_DIR)

help:
	@echo "Цели:"
	@echo "  all      - собрать всё"
	@echo "  app      - только приложение"
	@echo "  plugins  - только плагины"
	@echo "  run      - собрать и запустить"
	@echo "  clean    - удалить артефакты"