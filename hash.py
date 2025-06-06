import hashlib
import secrets
import getpass

def hash_password(password):
    salt = secrets.token_hex(8)  # Генерируем 8-байтовую соль (16 hex символов)
    salted_password = salt + password
    hashed = hashlib.sha256(salted_password.encode()).hexdigest()
    return f"{salt}${hashed}"

def main():
    while True:
        # Запрос пароля без отображения в консоли
        password = getpass.getpass("\nВведите пароль: ")
        confirm = getpass.getpass("Подтвердите пароль: ")
        
        if password != confirm:
            print("\nОшибка: Пароли не совпадают. Попробуйте снова.")
            continue
        
        if not password:
            print("\nОшибка: Пароль не может быть пустым.")
            continue
            
        hashed_password = hash_password(password)
        
        print(f"\nПолученный хеш: {hashed_password}")
        #print(f"Длина: {len(hashed_password)} символов")
        
        repeat = input("\nСгенерировать еще один хеш? (y/n): ").lower()
        if repeat != 'y':
            break

if __name__ == "__main__":
    main()