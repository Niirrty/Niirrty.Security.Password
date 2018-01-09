<?php
/**
 * @author         Ni Irrty <niirrty+code@gmail.com>
 * @copyright  (c) 2017, Ni Irrty
 * @package        Niirrty\Security\Password
 * @since          2018-01-08
 */


declare( strict_types = 1 );


namespace Niirrty\Security\Password;


use \Niirrty\DB\Driver\SQLite as SQLiteDriver;


/**
 * Checks the security (quality) of a password.
 *
 * Simple init it by constructor and get the result by ->getQuality()
 *
 * The returned value is a integer between 0 (none) and 10 (best)
 *
 * @package Niirrty\Security\Password
 */
class PasswordSecurityCheck
{


   // <editor-fold desc="// –––––––   P R O T E C T E D   F I E L D S   ––––––––––––––––––––––––––––––––––">

   /**
    * The password length
    *
    * @type int
    */
   protected $_length;

   /**
    * All unique chars as array
    *
    * @type array
    */
   protected $_charsUnique;

   /**
    * Defines if the password is known in top 10|25|50 by one of the SecList
    * {@link https://github.com/danielmiessler/SecLists} password lists.
    *
    * If known in top 10 the value is 10, if known in top 25 the value is 25 and in known in top 50 the value is 50.
    * Otherwise, if not known in one of the lists, the value is NULL
    *
    * @type int
    */
   protected $_topList;

   /**
    * Amount of password letters in lower case.
    *
    * @type int
    */
   protected $_lettersLower;

   /**
    * Amount of password letters in upper case.
    *
    * @type int
    */
   protected $_lettersUpper;

   /**
    * Amount of password number chars.
    *
    * @type int
    */
   protected $_numbers;

   /**
    * Amount of all other password chars.
    *
    * @type int
    */
   protected $_others;

   /**
    * The calculated char diversity quality.
    *
    * It is calculated by:
    *
    * - 0  = 0 different chars
    * - 1  = 1 char at all
    * - 2  = 2 different chars
    * - 3  = 3 different chars
    * - 5  = 4 different chars
    * - 6  = 5 different chars
    * - 8  = 6 different chars
    * - 9  = 7 different chars
    * - 10 = 8+ different chars
    *
    * @type int
    */
   protected $_charDiversityQuality;

   /**
    * The char type diversity quality.
    *
    * It is calculated by:
    *
    * - +2  for 1-n lower case letters
    * - +2  for 1-n upper case letters
    * - +2  for 1-n numbers
    * - +4  for 1-n other chars
    *
    * @type int
    */
   protected $_charTypeDiversityQuality;

   /**
    * The quality, depending to the password length.
    *
    * It is calculated by:
    *
    * - 0  = 0-1 chars password length
    * - 1  = 2  chars password length
    * - 2  = 3  chars password length
    * - 3  = 4  chars password length
    * - 4  = 5  chars password length
    * - 5  = 6  chars password length
    * - 6  = 7  chars password length
    * - 7  = 8  chars password length
    * - 8  = 9  chars password length
    * - 9  = 10 chars password length
    * - 10 = 11-n chars password length
    *
    * @type int
    */
   protected $_lengthQuality;

   /**
    * The quality relation to TOP 10/25/50 Lists
    *
    * - 10 = Not in a list
    * - 5  = Only in TOP 50 list of known passwords
    * - 3  = In TOP 25 list of known passwords
    * - 1  = In TOP 10 list of known passwords
    *
    * @type int
    */
   protected $_knownQuality;

   /**
    * @type int|null
    */
   protected $_quality = null;

   // </editor-fold>


   private const CHAR_DIVERSITY_QUALITIES = [
      0  => 0,
      1  => 1,
      2  => 2,
      3  => 3,
      4  => 5,
      5  => 6,
      6  => 8,
      7  => 9
   ];


   // <editor-fold desc="// –––––––   C O N S T R U C T O R   A N D / O R   D E S T R U C T O R   ––––––––">

   /**
    * Init a new PasswordSecurityCheck instance.
    */
   public function __construct( string $password )
   {

      // Get the password length
      $this->_length = \mb_strlen( $password );

      // Split password into chars array
      $chars = \preg_split( '//u', $password, -1, PREG_SPLIT_NO_EMPTY );

      // Get a list of all used chars
      $this->_charsUnique = \array_unique( $chars );

      $this->_topList = 0;

      $this->_lettersLower = (int) \preg_match_all( '~[a-z]~', $password );
      $this->_lettersUpper = (int) \preg_match_all( '~[A-Z]~', $password );
      $this->_numbers      = (int) \preg_match_all( '~\d~', $password );
      $this->_others       = $this->_length - $this->_lettersLower - $this->_lettersUpper - $this->_numbers;

      /*
       * - 0  = 0 different chars
       * - 1  = 1 char at all
       * - 2  = 2 different chars
       * - 3  = 3 different chars
       * - 5  = 4 different chars
       * - 6  = 5 different chars
       * - 8  = 6 different chars
       * - 9  = 7 different chars
       * - 10 = 8+ different chars
       */
      $charsUniqueCount = \count( $this->_charsUnique );
      if ( isset( self::CHAR_DIVERSITY_QUALITIES[ $charsUniqueCount ] ) )
      {
         $this->_charDiversityQuality = self::CHAR_DIVERSITY_QUALITIES[ $charsUniqueCount ];
      }
      else
      {
         $this->_charDiversityQuality = 10;
      }

      /*
       * - +2  for 1-n lower case letters
       * - +2  for 1-n upper case letters
       * - +2  for 1-n numbers
       * - +4  for 1-n other chars
       * _charTypeDiversityQuality
       */
      $this->_charTypeDiversityQuality = 0;
      if ( $this->_lettersUpper > 0 ) { $this->_charTypeDiversityQuality += 2; }
      if ( $this->_lettersLower > 0 ) { $this->_charTypeDiversityQuality += 2; }
      if ( $this->_numbers      > 0 ) { $this->_charTypeDiversityQuality += 2; }
      if ( $this->_others       > 0 ) { $this->_charTypeDiversityQuality += 4; }

      /*
       * - 0  = 0-1 chars password length
       * - 1  = 2  chars password length
       * - 2  = 3  chars password length
       * - 3  = 4  chars password length
       * - 4  = 5  chars password length
       * - 5  = 6  chars password length
       * - 6  = 7  chars password length
       * - 7  = 8  chars password length
       * - 8  = 9  chars password length
       * - 9  = 10 chars password length
       * - 10 = 11-n chars password length
       */
      if ( $this->_length < 2         ) { $this->_lengthQuality = 0; }
      else if ( $this->_length === 2  ) { $this->_lengthQuality = 1; }
      else if ( $this->_length === 3  ) { $this->_lengthQuality = 2; }
      else if ( $this->_length === 4  ) { $this->_lengthQuality = 3; }
      else if ( $this->_length === 5  ) { $this->_lengthQuality = 4; }
      else if ( $this->_length === 6  ) { $this->_lengthQuality = 5; }
      else if ( $this->_length === 7  ) { $this->_lengthQuality = 6; }
      else if ( $this->_length === 8  ) { $this->_lengthQuality = 7; }
      else if ( $this->_length === 9  ) { $this->_lengthQuality = 8; }
      else if ( $this->_length === 10 ) { $this->_lengthQuality = 9; }
      #else if ( $this->_length >= 11 ) { $this->_lengthQuality = 10; }
      else                              { $this->_lengthQuality = 10; }

      $driver = ( new SQLiteDriver() )
         ->setDb( \dirname( __DIR__ ) . '/data/toplists.sqlite' );
      $conn = new \Niirrty\DB\Connection( $driver );
      if ( 0 < (int) $conn->fetchScalar( 'SELECT COUNT(*) FROM pwd_top10 WHERE p10_password = ?',
                                         [ $password ], 0 ) )
      {
         $this->_knownQuality = 1;
         $this->_topList = 10;
      }
      else if ( 0 < (int) $conn->fetchScalar( 'SELECT COUNT(*) FROM pwd_top25 WHERE p25_password = ?',
            [ $password ], 0 ) )
      {
         $this->_knownQuality = 3;
         $this->_topList = 25;
      }
      else if ( 0 < (int) $conn->fetchScalar( 'SELECT COUNT(*) FROM pwd_top50 WHERE p50_password = ?',
            [ $password ], 0 ) )
      {
         $this->_knownQuality = 5;
         $this->_topList = 50;
      }
      else
      {
         $this->_knownQuality = 10;
      }

   }

   // </editor-fold>


   // <editor-fold desc="// –––––––   P U B L I C   M E T H O D S   ––––––––––––––––––––––––––––––––––––––">

   /**
    * Gets the password length.
    *
    * @return int
    */
   public function getLength() : int
   {

      return $this->_length;

   }

   /**
    * Gets all unique password chars as array
    *
    * @return array
    */
   public function getCharsUnique() : array
   {

      return $this->_charsUnique;

   }

   /**
    * Gets if the password is known in top 10|25|50 by one of the SecList
    * {@link https://github.com/danielmiessler/SecLists} password lists.
    *
    * If known in top 10 the value is 10, if known in top 25 the value is 25 and in known in top 50 the value is 50.
    * Otherwise, if not known in one of the lists, the value is NULL
    *
    * @return bool
    */
   public function getTopList() : int
   {

      return $this->_topList;

   }

   /**
    * Gets the amount of password letters in lower case.
    *
    * @return int
    */
   public function getLettersLower() : int
   {

      return $this->_lettersLower;

   }

   /**
    * Gets the amount of password letters in upper case.
    *
    * @return int
    */
   public function getLettersUpper() : int
   {

      return $this->_lettersUpper;

   }

   /**
    * Gets the amount of password number chars.
    *
    * @return int
    */
   public function getNumbers() : int
   {

      return $this->_numbers;

   }

   /**
    * Gets the amount of all other password chars.
    *
    * @return int
    */
   public function getOthers() : int
   {

      return $this->_others;

   }

   /**
    * Gets the calculated char diversity quality.
    *
    * It is calculated by:
    *
    * - 0  = 0 different chars
    * - 1  = 1 char at all
    * - 2  = 2 different chars
    * - 3  = 3 different chars
    * - 5  = 4 different chars
    * - 6  = 5 different chars
    * - 8  = 6 different chars
    * - 9  = 7 different chars
    * - 10 = 8+ different chars
    *
    * @return int
    */
   public function getCharDiversityQuality() : int
   {

      return $this->_charDiversityQuality;

   }

   /**
    * Gets the char type diversity quality.
    *
    * It is calculated by:
    *
    * - +2  for 1-n lower case letters
    * - +2  for 1-n upper case letters
    * - +2  for 1-n numbers
    * - +4  for 1-n other chars
    *
    * @return int
    */
   public function getCharTypeDiversityQuality() : int
   {

      return $this->_charTypeDiversityQuality;

   }

   /**
    * Gets the quality, depending to the password length.
    *
    * It is calculated by:
    *
    * - 0  = 0-1 chars password length
    * - 1  = 2  chars password length
    * - 2  = 3  chars password length
    * - 3  = 4  chars password length
    * - 4  = 5  chars password length
    * - 5  = 6  chars password length
    * - 6  = 7  chars password length
    * - 7  = 8  chars password length
    * - 8  = 9  chars password length
    * - 9  = 10 chars password length
    * - 10 = 11-n chars password length
    *
    * @return int
    */
   public function getLengthQuality() : int
   {

      return $this->_lengthQuality;

   }

   /**
    * Gets the quality relation to TOP 10/25/50 Lists
    *
    * - 10 = Not in a list
    * - 5  = Only in TOP 50 list of known passwords
    * - 3  = In TOP 25 list of known passwords
    * - 1  = In TOP 10 list of known passwords
    *
    * @return int
    */
   public function getKnownQuality() : int
   {

      return $this->_knownQuality;

   }

   /**
    * Gets the final calculated password quality. The value can be between
    * 0 (no usable password without security) and 10 (best password quality)
    * and always represents the lowest value from 'CharDiversityQuality', 'CharTypeDiversityQuality',
    * 'LengthQuality' and 'KnownQuality'
    *
    * All values higher than 5 are OK.
    *
    * @return int
    */
   public function getQuality() : int
   {

      if ( null === $this->_quality )
      {
         $this->_quality =
            \min(
               \min(
                  \min(
                     $this->_knownQuality,
                     $this->_charDiversityQuality
                  ),
                  $this->_charTypeDiversityQuality
               ),
               $this->_lengthQuality );
      }

      return $this->_quality;

   }

   // </editor-fold>


}

