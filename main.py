import hashlib
import imghdr
import io
import math
from typing import BinaryIO

from PIL import Image

from Crypto.Cipher import AES
import crc8


def main():
    dumpfilepath = './source/dump_009.DMP'
    encrfilepath = './source/encr_009'
    imagepath = './res/image1.png'
    image2path = './res/image2.jpeg'
    clean_image_path = './res/clear_image.jpeg'
    pwpath = './res/password.txt'

    # Task 1 ########
    # получим ключи
    dump = open(dumpfilepath, 'rb').read()
    keys = get_keys(dump)
    print("Потенциальных ключей: " + str(len(keys)))

    # достанем изображение
    encr = open(encrfilepath, 'rb').read()
    image, key = get_image(encr, keys)
    if image is None:
        print("Не подошёл ни один из переданных ключей")
        return
    else:
        with open(imagepath, 'wb') as f:
            f.write(image)
        print("Изображение было декодировано и сохранено по пути: " + imagepath)

    # Task 2 ########
    new_image = convert_image(image)
    with open(image2path, 'wb') as f:
        f.write(new_image)
        print("Изображение-сообщение было получено и сохранено по пути: " + image2path)

    # Task 3 ########
    clean = get_clean_image(new_image)
    clean.save(clean_image_path)
    pw = get_image_password(new_image, clean_image_path, key)
    print("Пароль: " + str(pw))
    print(str(pw).encode("utf-8"))
    with open(pwpath, 'wb') as f:
        f.write(pw)

    pass


def get_keys(data: bytes):
    all_keys = dict()
    key_length = 16
    min_unique = 15
    for i in range(len(data) - key_length):
        key_bytes = data[i:i + key_length]
        key = key_bytes
        if key in all_keys:
            all_keys[key]['counter'] += 1
        else:
            all_keys[key] = {
                'bytes': key_bytes,
                'counter': 1
            }
    keys = []
    for k, v in all_keys.items():
        unique_count = len(set(v['bytes']))
        if v['counter'] == 2 and unique_count >= min_unique:  # отсеим ключи с маленьким кол-вом различных символов
            keys.append(v['bytes'])
    return keys


def get_image(data: bytes, keys: list):
    for key in keys:
        decipher = AES.new(key, AES.MODE_ECB)
        img = decipher.decrypt(data)
        if is_png(img):
            return img, key
    return None, None


# по первым байтам выявляем png
def is_png(data: bytes):
    return data.startswith(bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]))


def is_jpeg(data: bytes):
    return data.startswith(bytes([0xFF, 0xD8, 0xFF, 0xE0]))


def convert_image(data: bytes):
    im = Image.open(io.BytesIO(data)).convert('RGBA')
    image1 = im.load()
    image2 = bytes()
    for y in range(im.height):
        for x in range(im.width):
            image_bytes = bytes(image1[x, y])
            changed_bytes = bytes([image_bytes[2], image_bytes[1], image_bytes[0], 0x00])
            new_bytes = bytes([my_crc8(changed_bytes)])
            image2 += bytes(new_bytes)
    return image2


def my_crc8(data: bytes):
    res = 0xff
    for b in data:
        res = (res ^ b)
        for j in range(8):
            res = ((res << 1) ^ 0x1D) if (res & 0x80) != 0 else (res << 1)
    res &= 0xFF
    res ^= 0xFF
    return res


def get_image_password(image: bytes, clean_image_path: str, key: bytes):
    start = 0
    for i in range(len(image)):
        if image[i] == 0xFF and image[i + 1] == 0xD9:
            start = i + 2
            break
    new_data = image[start:]
    with open(clean_image_path, 'rb') as f:
        clean = f.read()
    f.close()
    key_2 = hashlib.md5(clean).digest()
    decipher = AES.new(key_2, AES.MODE_CBC, IV=key)
    return decipher.decrypt(new_data)


def get_clean_image(data: bytes):
    image = Image.open(io.BytesIO(data))
    new_data = list(image.getdata())
    image_without_exif = Image.new(image.mode, image.size)
    image_without_exif.putdata(new_data)
    return image_without_exif


def test_crc8():
    s = "password".encode()
    print(bytes([my_crc8(s)]))
    for i in range(0xFF + 1):
        hash = crc8.crc8(s, i)
        # print(hash.hexdigest().encode())
        if hash.hexdigest().encode() == b'cf':
            print(bytes([i])[0])


if __name__ == '__main__':
    main()

