package io.dronekit.oauth

object URLEncoder {
  def encode(toEncode: String): String = {
    val encoded = new StringBuilder()

    for(ch <- toEncode.toCharArray()) {
      if (isUnsafe(ch)) {
        encoded.append('%')
        encoded.append(toHex(ch / 16));
        encoded.append(toHex(ch % 16));
      } else {
        encoded.append(ch)
      }
    }

    return encoded.toString()
  }

  def toHex(ch: Int): Char = {
    return (if(ch < 10) '0' + ch else 'A' + ch - 10).toChar
  }

  def isUnsafe(ch: Char): Boolean = {
    if (ch > 128 || ch < 0) {
      return true;
    }
    return " %$&+,/:;=?@<>#%[]".indexOf(ch) >= 0;
  }

}
