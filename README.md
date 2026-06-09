# earth-lamia

<img width="918" height="186" alt="ảnh" src="https://github.com/user-attachments/assets/ef350c46-49a9-458f-bbc9-3df0dc24ae1a" />

<img width="848" height="792" alt="ảnh" src="https://github.com/user-attachments/assets/803e8f44-5d99-49ac-84e5-393e3e51d4fc" />

<img width="843" height="784" alt="ảnh" src="https://github.com/user-attachments/assets/36d55ce6-2789-458f-9d00-5ada24ed2ea0" />

<img width="845" height="794" alt="ảnh" src="https://github.com/user-attachments/assets/6740ad0c-ea99-4afa-87eb-cb244b7f062c" />

Bài cho 1 file exe, 1 file dll fake userenv.dll bị pack bằng themida và 1 file dll đã bị mã hóa

debug chương trình:

<img width="1919" height="859" alt="ảnh" src="https://github.com/user-attachments/assets/84cfc484-439f-47b7-a9f4-9d9b6b19e6fa" />

Chương trình phát hiện debugger do có cơ chế antidebug của themida sau khi load USERENV.DLL

để bypass antidebug 1 cách nhanh nhất thì ta sử dụng scyllahide

<img width="1915" height="733" alt="ảnh" src="https://github.com/user-attachments/assets/8192edb4-e516-42fc-b6f7-1e894c81744d" />

<img width="1919" height="857" alt="ảnh" src="https://github.com/user-attachments/assets/07ddd5b3-8b89-4bd7-b6d1-d933389bf8d9" />

Bây giờ chương trình đã bypass antidebug và có thể debug bình thường

Để phân tích chương trình thì ta cần unpack themida

Tìm OEP: 

Ta đã biết rằng USERENV.DLL là file pe tự compile nên ta có thể đặt breakpoint ở `GetSystemTimeAsFileTime` để tìm oep

<img width="1328" height="366" alt="ảnh" src="https://github.com/user-attachments/assets/c8c03a10-f197-4905-822e-e3da117dd09a" />

Vậy oep nằm ở `USERENV.DLL + 0x2671c`

Fix Imports:

mở scylla:

<img width="1919" height="861" alt="ảnh" src="https://github.com/user-attachments/assets/6a26ac46-7c9f-4b63-8a75-04ed737d83b6" />

Phần lớn import đều là invalid scylla không parse được

Tìm đến IAT:

<img width="1321" height="320" alt="ảnh" src="https://github.com/user-attachments/assets/868d0752-0c6d-40f5-847f-8fe08fa660ab" />

<img width="1339" height="365" alt="ảnh" src="https://github.com/user-attachments/assets/7e8af3ab-1492-443d-a5a9-94003a10de29" />

<img width="1334" height="318" alt="ảnh" src="https://github.com/user-attachments/assets/1e3195ec-ecce-4509-a068-da8ae900fc64" />


các hàm tại IAT không trực tiếp trỏ đến API mà qua 1 trampoline rồi mới ret về API



