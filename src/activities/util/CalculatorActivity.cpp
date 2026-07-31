#include "CalculatorActivity.h"

#include <GfxRenderer.h>
#include <I18n.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

// Keypad layout, laid out like a calculator faceplate: digits on the left,
// operators down the right edge, clear/backspace in the last column.
const CalculatorActivity::Key CalculatorActivity::KEYS[CalculatorActivity::KEY_COUNT] = {
    {"7", '7', KeyAction::Append}, {"8", '8', KeyAction::Append},  {"9", '9', KeyAction::Append},
    {"/", '/', KeyAction::Append}, {"C", 0, KeyAction::Clear},

    {"4", '4', KeyAction::Append}, {"5", '5', KeyAction::Append},  {"6", '6', KeyAction::Append},
    {"*", '*', KeyAction::Append}, {"(", '(', KeyAction::Append},

    {"1", '1', KeyAction::Append}, {"2", '2', KeyAction::Append},  {"3", '3', KeyAction::Append},
    {"-", '-', KeyAction::Append}, {")", ')', KeyAction::Append},

    {"0", '0', KeyAction::Append}, {".", '.', KeyAction::Append},  {"=", 0, KeyAction::Equals},
    {"+", '+', KeyAction::Append}, {"<", 0, KeyAction::Backspace},
};

void CalculatorActivity::onEnter() {
  Activity::onEnter();
  requestUpdate();
}

void CalculatorActivity::skipSpaces(const char*& cursor) {
  while (*cursor == ' ' || *cursor == '\t') cursor++;
}

// primary := number | '(' expression ')'
bool CalculatorActivity::parsePrimary(const char*& cursor, double& out) {
  skipSpaces(cursor);

  if (*cursor == '(') {
    cursor++;
    if (!parseExpression(cursor, out)) return false;
    skipSpaces(cursor);
    if (*cursor != ')') return false;
    cursor++;
    return true;
  }

  if ((*cursor >= '0' && *cursor <= '9') || *cursor == '.') {
    char* end = nullptr;
    out = strtod(cursor, &end);
    if (end == cursor) return false;
    cursor = end;
    return true;
  }

  return false;
}

// unary := ('-' | '+') unary | primary
bool CalculatorActivity::parseUnary(const char*& cursor, double& out) {
  skipSpaces(cursor);
  if (*cursor == '-') {
    cursor++;
    if (!parseUnary(cursor, out)) return false;
    out = -out;
    return true;
  }
  if (*cursor == '+') {
    cursor++;
    return parseUnary(cursor, out);
  }
  return parsePrimary(cursor, out);
}

// power := unary ('^' power)?   -- right associative, so 2^3^2 == 2^9
bool CalculatorActivity::parsePower(const char*& cursor, double& out) {
  if (!parseUnary(cursor, out)) return false;
  skipSpaces(cursor);
  if (*cursor == '^') {
    cursor++;
    double exponent = 0;
    if (!parsePower(cursor, exponent)) return false;
    out = std::pow(out, exponent);
  }
  return true;
}

// term := power (('*' | '/' | '%') power)*
bool CalculatorActivity::parseTerm(const char*& cursor, double& out) {
  if (!parsePower(cursor, out)) return false;
  for (;;) {
    skipSpaces(cursor);
    const char op = *cursor;
    if (op != '*' && op != '/' && op != '%') return true;
    cursor++;
    double rhs = 0;
    if (!parsePower(cursor, rhs)) return false;
    if (op == '/' || op == '%') {
      if (rhs == 0.0) return false;
      out = op == '/' ? out / rhs : std::fmod(out, rhs);
    } else {
      out *= rhs;
    }
  }
}

// expression := term (('+' | '-') term)*
bool CalculatorActivity::parseExpression(const char*& cursor, double& out) {
  if (!parseTerm(cursor, out)) return false;
  for (;;) {
    skipSpaces(cursor);
    const char op = *cursor;
    if (op != '+' && op != '-') return true;
    cursor++;
    double rhs = 0;
    if (!parseTerm(cursor, rhs)) return false;
    out = op == '+' ? out + rhs : out - rhs;
  }
}

std::string CalculatorActivity::formatNumber(double value) {
  char buffer[32];
  snprintf(buffer, sizeof(buffer), "%.10g", value);
  return std::string(buffer);
}

void CalculatorActivity::evaluate() {
  hasError = false;
  result.clear();
  if (expression.empty()) return;

  const char* cursor = expression.c_str();
  double value = 0;
  const bool parsed = parseExpression(cursor, value);
  skipSpaces(cursor);

  // Trailing junk ("2+3)") is an error too, not a partial success.
  if (!parsed || *cursor != '\0' || !std::isfinite(value)) {
    hasError = true;
    return;
  }

  result = formatNumber(value);
}

void CalculatorActivity::pressSelected() {
  const Key& key = KEYS[selectedRow * GRID_COLS + selectedCol];

  switch (key.action) {
    case KeyAction::Clear:
      expression.clear();
      result.clear();
      hasError = false;
      break;

    case KeyAction::Backspace:
      if (!expression.empty()) expression.pop_back();
      hasError = false;
      break;

    case KeyAction::Equals:
      evaluate();
      break;

    case KeyAction::Append:
      // Typing after a result starts a fresh sum, the way a desk calculator does --
      // unless an operator is pressed, which continues from the result.
      if (!result.empty()) {
        const bool isOperator = key.character == '+' || key.character == '-' || key.character == '*' ||
                                key.character == '/' || key.character == '%' || key.character == '^';
        expression = isOperator ? result : std::string();
        result.clear();
      }
      if (expression.size() < EXPRESSION_MAX) expression += key.character;
      hasError = false;
      break;
  }
  requestUpdate();
}

void CalculatorActivity::loop() {
  using Button = MappedInputManager::Button;

  if (handleToolBack()) {
    return;
  }
  if (mappedInput.wasPressed(Button::Confirm)) {
    pressSelected();
    return;
  }
  if (mappedInput.wasPressed(Button::Left)) {
    selectedCol = (selectedCol + GRID_COLS - 1) % GRID_COLS;
    requestUpdate();
    return;
  }
  if (mappedInput.wasPressed(Button::Right)) {
    selectedCol = (selectedCol + 1) % GRID_COLS;
    requestUpdate();
    return;
  }
  if (mappedInput.wasPressed(Button::Up)) {
    selectedRow = (selectedRow + GRID_ROWS - 1) % GRID_ROWS;
    requestUpdate();
    return;
  }
  if (mappedInput.wasPressed(Button::Down)) {
    selectedRow = (selectedRow + 1) % GRID_ROWS;
    requestUpdate();
  }
}

void CalculatorActivity::render(RenderLock&&) {
  const auto& metrics = UITheme::getInstance().getMetrics();

  beginToolRender(tr(STR_CALCULATOR));

  const Rect content = toolContentRect();

  // Readout: the expression on top, the result (or the error) beneath it, both
  // right-aligned against the keypad's right edge like a calculator display.
  constexpr int EXPR_FONT_ID = UI_12_FONT_ID;
  constexpr int RESULT_FONT_ID = NOTOSANS_18_FONT_ID;
  const int exprHeight = renderer.getLineHeight(EXPR_FONT_ID);
  const int resultHeight = renderer.getLineHeight(RESULT_FONT_ID);
  const int readoutHeight = exprHeight + resultHeight + metrics.verticalSpacing;

  renderer.drawRect(content.x, content.y, content.width, readoutHeight, 1, true);

  const int textRight = content.x + content.width - metrics.contentSidePadding / 2;
  const int padLeft = content.x + metrics.contentSidePadding / 2;

  // Show the tail of a long expression: the digits being typed matter most.
  std::string shown = expression;
  const int maxTextWidth = content.width - metrics.contentSidePadding;
  while (shown.size() > 1 && renderer.getTextWidth(EXPR_FONT_ID, shown.c_str()) > maxTextWidth) shown.erase(0, 1);
  const int exprWidth = renderer.getTextWidth(EXPR_FONT_ID, shown.c_str());
  renderer.drawText(EXPR_FONT_ID, std::max(padLeft, textRight - exprWidth), content.y + metrics.verticalSpacing / 2,
                    shown.c_str(), true);

  const char* resultText = hasError ? tr(STR_CALC_INVALID) : result.c_str();
  if (resultText[0] != '\0') {
    const int resultFont = hasError ? EXPR_FONT_ID : RESULT_FONT_ID;
    const int resultWidth = renderer.getTextWidth(resultFont, resultText);
    renderer.drawText(resultFont, std::max(padLeft, textRight - resultWidth),
                      content.y + exprHeight + metrics.verticalSpacing / 2, resultText, true,
                      hasError ? EpdFontFamily::REGULAR : EpdFontFamily::BOLD);
  }

  // Keypad fills the space under the readout.
  const int gridTop = content.y + readoutHeight + metrics.verticalSpacing;
  const int gridHeight = content.y + content.height - gridTop;
  if (gridHeight <= 0) {
    endToolRender(tr(STR_BTN_BACK), tr(STR_SELECT), tr(STR_DIR_LEFT), tr(STR_DIR_RIGHT));
    return;
  }

  constexpr int KEY_GAP = 4;
  const int keyWidth = (content.width - KEY_GAP * (GRID_COLS - 1)) / GRID_COLS;
  const int keyHeight = (gridHeight - KEY_GAP * (GRID_ROWS - 1)) / GRID_ROWS;

  for (int row = 0; row < GRID_ROWS; row++) {
    for (int col = 0; col < GRID_COLS; col++) {
      const Key& key = KEYS[row * GRID_COLS + col];
      const Rect keyRect{content.x + col * (keyWidth + KEY_GAP), gridTop + row * (keyHeight + KEY_GAP), keyWidth,
                         keyHeight};
      const bool selected = row == selectedRow && col == selectedCol;
      // Reuse the on-screen keyboard's key styling so the pad looks native, with
      // "=" and backspace marked as special keys the way Ok/Del are there.
      KeyboardKeyType keyType = KeyboardKeyType::Normal;
      if (key.action == KeyAction::Equals) keyType = KeyboardKeyType::Ok;
      if (key.action == KeyAction::Backspace) keyType = KeyboardKeyType::Del;
      GUI.drawKeyboardKey(renderer, keyRect, key.label, selected, nullptr, keyType);
    }
  }

  endToolRender(tr(STR_BTN_BACK), tr(STR_SELECT), tr(STR_DIR_LEFT), tr(STR_DIR_RIGHT));
}
