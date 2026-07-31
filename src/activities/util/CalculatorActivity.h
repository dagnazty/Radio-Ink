#pragma once

#include <GfxRenderer.h>

#include <string>

#include "activities/util/ToolActivityBase.h"

// A calculator with an actual keypad: a 5x4 grid of keys on screen, moved around
// with the D-pad and pressed with Confirm, above a readout showing the expression
// being built and its result.
//
// Supports + - * / % ^, parentheses, and decimals, evaluated on "=" by a small
// recursive-descent parser (no heap, no exceptions).
class CalculatorActivity final : public ToolActivityBase {
 public:
  CalculatorActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : ToolActivityBase("Calculator", renderer, mappedInput, ToolItem::CALCULATOR) {}

  void onEnter() override;
  void loop() override;
  void render(RenderLock&&) override;

 private:
  // Keys that do something other than append their label to the expression.
  enum class KeyAction { Append, Equals, Clear, Backspace };

  struct Key {
    const char* label;
    char character;  // appended when action == Append
    KeyAction action;
  };

  static constexpr int GRID_COLS = 5;
  static constexpr int GRID_ROWS = 4;
  static constexpr int KEY_COUNT = GRID_COLS * GRID_ROWS;
  static constexpr size_t EXPRESSION_MAX = 64;

  static const Key KEYS[KEY_COUNT];

  std::string expression;
  std::string result;     // formatted result of the last "=", empty until then
  bool hasError = false;  // last "=" could not be evaluated
  int selectedRow = 0;
  int selectedCol = 0;

  void pressSelected();
  void evaluate();

  // Recursive-descent evaluator. Returns false on a malformed expression or a
  // division by zero; `cursor` is advanced past whatever was consumed.
  static bool parseExpression(const char*& cursor, double& out);
  static bool parseTerm(const char*& cursor, double& out);
  static bool parsePower(const char*& cursor, double& out);
  static bool parseUnary(const char*& cursor, double& out);
  static bool parsePrimary(const char*& cursor, double& out);
  static void skipSpaces(const char*& cursor);

  // Trims a double to the shortest readable form ("7" not "7.0000000000").
  static std::string formatNumber(double value);
};
